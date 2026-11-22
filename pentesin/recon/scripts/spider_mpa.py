#!/usr/bin/env python3
"""
spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "k=v; k2=v2"] [--max 150] [--depth 4]

Bounded MPA HTML form, link, and inline-JS AJAX crawler adapted from ARTEX.
Writes forms.txt, links.txt, and api_inline.txt inside OUTDIR.
"""

from __future__ import annotations

import argparse
import contextlib
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from collections import deque
from html.parser import HTMLParser
from pathlib import Path


CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (spa-api-recon spider)"
SKIP_EXT = re.compile(
    r"\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|pdf|zip|mp4|webp|js)(\?|$)", re.I
)
API_HINT = re.compile(
    r"/(?:api|rest|service|ajax|action|do|rpc|graphql|v\d|admin|backend)\b", re.I
)


def fetch(url: str, cookie: str) -> tuple[str, str]:
    if not url.startswith(("http://", "https://")):
        return "", ""
    headers = {"User-Agent": UA}
    if cookie:
        headers["Cookie"] = cookie
    try:
        req = urllib.request.Request(url, headers=headers)  # noqa: S310
        with urllib.request.urlopen(req, context=CTX, timeout=20) as resp:  # noqa: S310
            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct and "xml" not in ct:
                return "", ct
            return resp.read().decode("utf-8", "ignore"), ct
    except Exception:  # noqa: BLE001
        return "", ""


class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inline: list[str] = []
        self.forms: list[dict[str, object]] = []
        self._cur: dict[str, object] | None = None
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        if tag == "a" and attr_map.get("href"):
            self.links.append(attr_map["href"] or "")
        elif tag == "script":
            self._in_script = True
            if attr_map.get("src"):
                self.scripts.append(attr_map["src"] or "")
        elif tag == "form":
            self._cur = {
                "action": attr_map.get("action") or "",
                "method": (attr_map.get("method") or "GET").upper(),
                "params": [],
            }
        elif tag in ("input", "select", "textarea", "button") and self._cur is not None:
            name = attr_map.get("name")
            if name and isinstance(self._cur["params"], list):
                self._cur["params"].append(name)
        for val in attr_map.values():
            for match in re.findall(r"""["'](/[^"']{2,120})["']""", val or ""):
                if API_HINT.search(match):
                    self.inline.append(match)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False
        elif tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def handle_data(self, data: str) -> None:
        if self._in_script and data:
            for match in re.findall(r"""["'`](/[A-Za-z0-9_\-./{}$:?=&]{2,120})["'`]""", data):
                if API_HINT.search(match):
                    self.inline.append(match)


def _enqueue_links(
    *,
    parser: Page,
    base_url: str,
    origin: str,
    depth: int,
    max_depth: int,
    inc: re.Pattern[str] | None,
    exc: re.Pattern[str] | None,
    seen: set[str],
    queue: deque[tuple[str, int]],
) -> None:
    if depth >= max_depth:
        return
    for href in parser.links:
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        nxt = urllib.parse.urljoin(base_url, href).split("#")[0]
        if not nxt.startswith(origin) or SKIP_EXT.search(nxt):
            continue
        if (exc and exc.search(nxt)) or (inc and not inc.search(nxt)):
            continue
        if nxt not in seen:
            seen.add(nxt)
            queue.append((nxt, depth + 1))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("outdir")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--max", type=int, default=150)
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.05)
    ap.add_argument("--include", default="")
    ap.add_argument("--exclude", default="logout|signout|delete|remove|destroy")
    args = ap.parse_args()

    base = args.base if args.base.startswith("http") else "https://" + args.base
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    parsed_base = urllib.parse.urlparse(base)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    inc = re.compile(args.include) if args.include else None
    exc = re.compile(args.exclude, re.I) if args.exclude else None

    seen: set[str] = {base.split("#")[0]}
    forms: dict[str, set[str]] = {}
    inline: set[str] = set()
    links: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(base, 0)])
    pages = 0

    while queue and pages < args.max:
        url, depth = queue.popleft()
        pages += 1
        html, _ct = fetch(url, args.cookie)
        if args.delay:
            time.sleep(args.delay)
        if not html:
            continue
        parser = Page()
        with contextlib.suppress(Exception):
            parser.feed(html)
        links.add(url.replace(origin, "") or "/")
        for form in parser.forms:
            action = str(form.get("action") or "")
            method = str(form.get("method") or "GET")
            act = urllib.parse.urljoin(url, action or url)
            key = f"{method} {act.replace(origin, '')}"
            raw_params = form.get("params")
            param_list = raw_params if isinstance(raw_params, list) else []
            forms.setdefault(key, set()).update(str(p) for p in param_list)
        inline.update(parser.inline)
        _enqueue_links(
            parser=parser,
            base_url=url,
            origin=origin,
            depth=depth,
            max_depth=args.depth,
            inc=inc,
            exc=exc,
            seen=seen,
            queue=queue,
        )

    forms_lines = [f"{k}  [{', '.join(sorted(forms[k]))}]" for k in sorted(forms)]
    (outdir / "forms.txt").write_text("\n".join(forms_lines), encoding="utf-8")
    (outdir / "links.txt").write_text("\n".join(sorted(links)), encoding="utf-8")
    (outdir / "api_inline.txt").write_text("\n".join(sorted(inline)), encoding="utf-8")
    sys.stdout.write(
        f"[+] crawled={pages} forms={len(forms)} inline={len(inline)} links={len(links)}\n"
    )


if __name__ == "__main__":
    main()
