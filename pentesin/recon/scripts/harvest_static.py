#!/usr/bin/env python3
"""
harvest_static.py <BASE_URL> <OUTDIR>

Static SPA bundle harvester adapted from ARTEX (BaaRai/ARTEX skills/api-recon).
  1. Fetch entry HTML, collect script/module references.
  2. Parse webpack + Vite chunk manifests and download reachable chunks.
  3. Extract API endpoints and route paths from all downloaded JS.

Stdlib only. TLS verification is disabled for self-signed/lab targets.
"""

from __future__ import annotations

import contextlib
import re
import ssl
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (spa-api-recon)"

API_HINT = re.compile(
    r"/(?:api|rest|service|services|gateway|graphql|v\d|web|admin|backend|open)\b", re.I
)
ASSET_EXT = re.compile(
    r"\.(js|css|png|jpe?g|svg|gif|woff2?|ttf|ico|map|json|mp4|webp)(\?|$)", re.I
)


def fetch(url: str, binary: bool = False) -> tuple[str | bytes, int]:
    if not url.startswith(("http://", "https://")):
        return (b"" if binary else ""), 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})  # noqa: S310
        with urllib.request.urlopen(req, context=CTX, timeout=25) as r:  # noqa: S310
            data = r.read()
            return (data if binary else data.decode("utf-8", "ignore")), int(r.status)
    except Exception as exc:  # noqa: BLE001
        code = int(getattr(exc, "code", 0) or 0)
        return (b"" if binary else ""), code


def origin_of(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def matched_block(text: str, end_brace_idx: int) -> str:
    """Walk back from a '}' index to its matching '{' and return the object body."""
    depth = 0
    idx = end_brace_idx
    while idx >= 0:
        if text[idx] == "}":
            depth += 1
        elif text[idx] == "{":
            depth -= 1
            if depth == 0:
                return text[idx : end_brace_idx + 1]
        idx -= 1
    return ""


def parse_chunk_maps(js_text: str) -> list[tuple[list[str], dict[str, str]]]:
    """Return list of (publicPath_hint, {id: hash}) for webpack and Vite chunk maps."""
    maps: list[tuple[list[str], dict[str, str]]] = []
    pubs = re.findall(r'(?:\.p|publicPath)\s*=\s*"([^"]*)"', js_text)
    for match in re.finditer(r'\}\[[A-Za-z_$]\]\s*\+\s*"\.js"', js_text):
        body = matched_block(js_text, match.start())
        pairs = re.findall(r'(\d+):"([0-9a-fA-F]{6,16})"', body)
        if pairs:
            maps.append((pubs, dict(pairs)))
    maps.extend(
        (["/"], {"__vite__": filename})
        for filename in re.findall(r'"(assets/[^"]+\.js)"', js_text)
    )
    return maps


def chunk_urls(base: str, js_text: str) -> set[str]:
    """Yield absolute chunk URLs reconstructable from this file's manifest(s)."""
    origin = origin_of(base)
    out: set[str] = set()
    for pubs, idmap in parse_chunk_maps(js_text):
        paths = pubs or ["/assets/", "/"]
        for cid, chunk_hash in idmap.items():
            if cid == "__vite__":
                out.update(urllib.parse.urljoin(origin + "/", chunk_hash) for _pp in paths)
                continue
            for pp in paths:
                if pp.startswith("http"):
                    bareorigin = ""
                    prefix = pp
                else:
                    bareorigin = origin
                    prefix = pp if pp.startswith("/") else "/" + pp
                if not prefix.endswith("/"):
                    prefix += "/"
                out.add(f"{bareorigin}{prefix}{cid}.{chunk_hash}.js")
    return out


def extract_endpoints(js_text: str) -> tuple[set[str], set[str]]:
    paths: set[str] = set()
    paths.update(re.findall(r"""["'`](/[A-Za-z0-9_\-./{}$:]+)["'`]""", js_text))
    paths.update(re.findall(r"""["'](/[A-Za-z0-9_\-./]+/)["']\s*\+""", js_text))
    api: set[str] = set()
    other: set[str] = set()
    for path in paths:
        if ASSET_EXT.search(path):
            continue
        if path.count("/") < 2 and not API_HINT.search(path):
            continue
        (api if API_HINT.search(path) else other).add(path)
    return api, other


def extract_routes(js_text: str) -> set[str]:
    routes: set[str] = set()
    for key in ("path", "to", "redirect", "href"):
        for match in re.findall(key + r"""\s*:\s*["'](/[A-Za-z0-9_\-/:]*)["']""", js_text):
            if not ASSET_EXT.search(match) and not API_HINT.search(match):
                routes.add(match)
    return routes


def _download_js(url: str, jsdir: Path, have: dict[str, Path]) -> Path | None:
    fn = Path(urllib.parse.urlparse(url).path).name
    if not fn.endswith(".js"):
        return None
    if url in have:
        return have[url]
    data, st = fetch(url, binary=True)
    raw_bytes = data if isinstance(data, bytes) else data.encode("utf-8", "ignore")
    if st == 200 and raw_bytes and not raw_bytes[:15].lstrip().startswith(b"<"):
        lp = jsdir / fn
        lp.write_bytes(raw_bytes)
        have[url] = lp
        return lp
    return None


def _expand_chunks(base: str, jsdir: Path, have: dict[str, Path]) -> set[str]:
    seen_urls = set(have.keys())
    frontier = list(have.values())
    for _ in range(6):
        if not frontier:
            break
        new_urls: set[str] = set()
        for lp in frontier:
            try:
                txt = lp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            new_urls.update(cu for cu in chunk_urls(base, txt) if cu not in seen_urls)
        seen_urls |= new_urls
        if not new_urls:
            break
        before = set(have.values())
        with ThreadPoolExecutor(max_workers=24) as ex:
            list(ex.map(lambda u: _download_js(u, jsdir, have), new_urls))
        frontier = [p for p in have.values() if p not in before]

    all_manifest: set[str] = set()
    for lp in list(have.values()):
        with contextlib.suppress(OSError):
            all_manifest |= chunk_urls(base, lp.read_text(encoding="utf-8", errors="ignore"))
    missing = [u for u in all_manifest if u not in have]
    if missing:
        with ThreadPoolExecutor(max_workers=24) as ex:
            list(ex.map(lambda u: _download_js(u, jsdir, have), missing))
    return all_manifest


def _extract_all(
    have: dict[str, Path],
    all_manifest: set[str],
    outdir: Path,
) -> tuple[set[str], set[str], set[str]]:
    api: set[str] = set()
    other: set[str] = set()
    routes: set[str] = set()
    for lp in have.values():
        try:
            txt = lp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        a, o = extract_endpoints(txt)
        api |= a
        other |= o
        routes |= extract_routes(txt)

    (outdir / "api_static.txt").write_text("\n".join(sorted(api)), encoding="utf-8")
    (outdir / "paths_other.txt").write_text("\n".join(sorted(other)), encoding="utf-8")
    (outdir / "routes.txt").write_text("\n".join(sorted(routes)), encoding="utf-8")
    (outdir / "chunkmap.txt").write_text(
        "\n".join(sorted(Path(urllib.parse.urlparse(u).path).name for u in all_manifest)),
        encoding="utf-8",
    )
    return api, other, routes


def main() -> None:
    if len(sys.argv) < 3:
        sys.stdout.write("usage: harvest_static.py <BASE_URL> <OUTDIR>\n")
        sys.exit(1)
    base = sys.argv[1] if sys.argv[1].startswith("http") else "https://" + sys.argv[1]
    outdir = Path(sys.argv[2])
    jsdir = outdir / "js"
    jsdir.mkdir(parents=True, exist_ok=True)

    html_raw, _status = fetch(base)
    html = html_raw if isinstance(html_raw, str) else html_raw.decode("utf-8", "ignore")
    (outdir / "index.html").write_text(html, encoding="utf-8")

    srcs = set(re.findall(r'<script[^>]+src="([^"]+\.js[^"]*)"', html))
    srcs |= set(re.findall(r'(?:src|href)="([^"]*\.js)"', html))
    seed = {s if s.startswith("http") else urllib.parse.urljoin(base, s) for s in srcs}

    have: dict[str, Path] = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(lambda u: _download_js(u, jsdir, have), seed))

    all_manifest = _expand_chunks(base, jsdir, have)
    api, other, routes = _extract_all(have, all_manifest, outdir)
    sys.stdout.write(
        f"[+] downloaded={len(have)} api={len(api)} other={len(other)} routes={len(routes)}\n"
    )


if __name__ == "__main__":
    main()
