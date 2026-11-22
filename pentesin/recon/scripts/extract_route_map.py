#!/usr/bin/env python3
"""
extract_route_map.py <JSDIR> <OUTDIR>

Scan downloaded JS chunks for routeMap / routeLink style objects adapted from ARTEX:
  KEY:{name:"...",link:"/path"}
Writes route_map.json when matches are found.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) < 3:
        sys.stdout.write("usage: extract_route_map.py <JSDIR> <OUTDIR>\n")
        sys.exit(1)
    jsdir = Path(sys.argv[1])
    outdir = Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)

    best: dict[str, dict[str, str]] = {}
    best_file: Path | None = None
    pat = re.compile(r'([A-Z_][A-Z0-9_]*):\{name:"([^"]*)",link:"([^"]+)"')

    for fp in jsdir.glob("*.js"):
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        hits = pat.findall(txt)
        if len(hits) > len(best):
            best = {k: {"name": n, "link": link} for k, n, link in hits}
            best_file = fp

    if not best:
        sys.stdout.write("[!] no routeMap pattern found\n")
        return

    out = outdir / "route_map.json"
    out.write_text(json.dumps(best, ensure_ascii=False, indent=2), encoding="utf-8")
    name = best_file.name if best_file else ""
    sys.stdout.write(f"[+] {len(best)} routes from {name} -> {out}\n")


if __name__ == "__main__":
    main()
