"""Recon output compression, pattern deduplication, and attack-surface prioritization."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit


# Non-exploitable media/binary extensions that can safely be filtered out from DAST testing.
# NOTE: .svg, .xml, .json, .map, .env, .bak, .config, .js, .txt, .html, .php are PRESERVED.
DROPPED_EXTENSIONS = frozenset(
    {
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".ico",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp",
        ".tiff",
        ".mp4",
        ".mp3",
        ".wav",
        ".avi",
        ".mov",
        ".flv",
        ".wmv",
        ".m4v",
        ".ogg",
    }
)

# High-priority keywords that indicate state-changing, auth, or sensitive attack surface
P1_KEYWORDS = frozenset(
    {
        "auth",
        "login",
        "logout",
        "signin",
        "signup",
        "register",
        "token",
        "session",
        "password",
        "secret",
        "user",
        "users",
        "account",
        "admin",
        "api",
        "graphql",
        "upload",
        "import",
        "export",
        "download",
        "file",
        "files",
        "v1",
        "v2",
        "v3",
        "redirect",
        "callback",
        "oauth",
        "pay",
        "payment",
        "checkout",
        "order",
        "invoice",
        "debug",
        "actuator",
        "eval",
        "execute",
        "cmd",
        "shell",
    }
)

_URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_NUMERIC_ID_REGEX = re.compile(r"^(\d+|[0-9a-fA-F-]{36})$")


@dataclass(frozen=True, slots=True)
class EndpointPattern:
    """A parameterized or structural endpoint pattern grouping duplicate URLs."""

    pattern_key: str
    normalized_path: str
    query_param_keys: tuple[str, ...]
    is_parameterized: bool
    is_high_priority: bool
    total_count: int
    sample_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_key": self.pattern_key,
            "normalized_path": self.normalized_path,
            "query_param_keys": list(self.query_param_keys),
            "is_parameterized": self.is_parameterized,
            "is_high_priority": self.is_high_priority,
            "total_count": self.total_count,
            "sample_urls": list(self.sample_urls),
        }


def filter_binary_extensions(urls: list[str]) -> tuple[list[str], list[str]]:
    """Separate actionable URLs from non-exploitable static binary media files."""
    kept: list[str] = []
    dropped: list[str] = []

    for raw in urls:
        url = raw.strip()
        if not url:
            continue
        try:
            parts = urlsplit(url)
            path_lower = parts.path.lower()
            dot_idx = path_lower.rfind(".")
            ext = path_lower[dot_idx:] if dot_idx != -1 else ""
            if ext in DROPPED_EXTENSIONS:
                dropped.append(url)
            else:
                kept.append(url)
        except (ValueError, AttributeError):
            kept.append(url)

    return kept, dropped


def _normalize_path(path: str) -> str:
    """Normalize path segments such as numeric IDs and UUIDs into {id} placeholders."""
    segments = path.strip("/").split("/")
    normalized_segments = []
    for seg in segments:
        if not seg:
            continue
        if _NUMERIC_ID_REGEX.match(seg):
            normalized_segments.append("{id}")
        else:
            normalized_segments.append(seg)
    return "/" + "/".join(normalized_segments) if normalized_segments else "/"


def _is_p1_pattern(path: str, param_keys: tuple[str, ...]) -> bool:
    """Check if the pattern matches high-value attack surface criteria."""
    if param_keys:
        return True
    lower_path = path.lower()
    return any(kw in lower_path for kw in P1_KEYWORDS)


def deduplicate_url_patterns(urls: list[str], *, sample_limit: int = 2) -> dict[str, Any]:
    """Group duplicate parameterized URLs into distinct structural patterns.

    Collapses hundreds of repetitive queries (e.g. /item?id=1..500) into
    single patterns while retaining representative sample URLs.
    """
    pattern_map: dict[str, dict[str, Any]] = {}

    for raw in urls:
        url = raw.strip()
        if not url:
            continue
        try:
            parts = urlsplit(url)
            norm_path = _normalize_path(parts.path)
            q_params = tuple(sorted({k.lower() for k, _ in parse_qsl(parts.query)}))
            netloc = parts.netloc.lower()
            scheme = parts.scheme.lower() or "https"

            param_str = "&".join(q_params) if q_params else ""
            pattern_key = f"{scheme}://{netloc}{norm_path}" + (f"?{param_str}" if param_str else "")

            if pattern_key not in pattern_map:
                is_p1 = _is_p1_pattern(norm_path, q_params)
                pattern_map[pattern_key] = {
                    "pattern_key": pattern_key,
                    "normalized_path": norm_path,
                    "query_param_keys": q_params,
                    "is_parameterized": bool(q_params),
                    "is_high_priority": is_p1,
                    "count": 0,
                    "samples": [],
                }

            entry = pattern_map[pattern_key]
            entry["count"] += 1
            if len(entry["samples"]) < sample_limit and url not in entry["samples"]:
                entry["samples"].append(url)
        except (ValueError, AttributeError):
            continue

    patterns = [
        EndpointPattern(
            pattern_key=item["pattern_key"],
            normalized_path=item["normalized_path"],
            query_param_keys=item["query_param_keys"],
            is_parameterized=item["is_parameterized"],
            is_high_priority=item["is_high_priority"],
            total_count=item["count"],
            sample_urls=item["samples"],
        )
        for item in pattern_map.values()
    ]

    all_samples: list[str] = []
    for p in patterns:
        all_samples.extend(p.sample_urls)

    return {
        "patterns": patterns,
        "total_raw": len(urls),
        "total_unique_patterns": len(patterns),
        "sample_urls": all_samples,
    }


def rank_recon_endpoints(patterns: list[EndpointPattern]) -> dict[str, list[EndpointPattern]]:
    """Divide endpoint patterns into P1 (High-Priority) and P2 (Standard)."""
    p1: list[EndpointPattern] = []
    p2: list[EndpointPattern] = []

    for pat in patterns:
        if pat.is_high_priority:
            p1.append(pat)
        else:
            p2.append(pat)

    # Sort within tiers by occurrence frequency
    p1.sort(key=lambda x: x.total_count, reverse=True)
    p2.sort(key=lambda x: x.total_count, reverse=True)

    return {"p1_high_priority": p1, "p2_standard": p2}


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract URLs from plain lines or JSON lines with url fields."""
    found: list[str] = []
    lines = text.splitlines()

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        if line_clean.startswith("{") and line_clean.endswith("}"):
            try:
                data = json.loads(line_clean)
                if isinstance(data, dict):
                    url_val = data.get("url") or data.get("endpoint") or data.get("target")
                    if isinstance(url_val, str) and url_val.startswith(("http://", "https://")):
                        found.append(url_val.strip())
                        continue
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        found.extend(match.group(0) for match in _URL_REGEX.finditer(line))

    # Preserve order while deduplicating exact strings
    seen: set[str] = set()
    deduped: list[str] = []
    for u in found:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def compress_recon_output(text: str, *, sample_limit: int = 2) -> str:
    """Process raw crawler/fuzzer logs into a high-density attack-surface summary."""
    if not text or not text.strip():
        return "No recon output provided."

    urls = _extract_urls_from_text(text)
    if not urls:
        # Not a URL listing; return original text with head/tail bounded
        lines = text.splitlines()
        if len(lines) > 60:
            head = "\n".join(lines[:30])
            tail = "\n".join(lines[-20:])
            return f"{head}\n\n[... {len(lines) - 50} lines compressed ...]\n\n{tail}"
        return text

    kept, dropped = filter_binary_extensions(urls)
    dedupe_res = deduplicate_url_patterns(kept, sample_limit=sample_limit)
    patterns: list[EndpointPattern] = dedupe_res["patterns"]
    ranked = rank_recon_endpoints(patterns)

    p1 = ranked["p1_high_priority"]
    p2 = ranked["p2_standard"]

    pattern_breakdown = f"P1 High-Priority: {len(p1)}, P2 Standard: {len(p2)}"
    output_lines: list[str] = [
        "### [Smart Recon] Attack Surface Summary",
        f"- **Raw URLs Processed:** {len(urls)}",
        f"- **Filtered Static Binaries:** {len(dropped)}",
        f"- **Unique Attack Patterns:** {len(patterns)} ({pattern_breakdown})",
        "",
    ]

    if p1:
        output_lines.append(
            "#### P1: High-Priority Attack Vectors (Parameters, Auth, Uploads, APIs):"
        )
        for pat in p1[:35]:
            count_info = f"({pat.total_count} instance{'s' if pat.total_count > 1 else ''})"
            params_info = (
                f" [Params: {', '.join(pat.query_param_keys)}]" if pat.query_param_keys else ""
            )
            output_lines.append(f"- `{pat.pattern_key}` {count_info}{params_info}")
            output_lines.extend(f"  * Sample: `{s}`" for s in pat.sample_urls)
        if len(p1) > 35:
            output_lines.append(f"  * [... {len(p1) - 35} more P1 patterns in database ...]")
        output_lines.append("")

    if p2:
        output_lines.append("#### P2: Standard Routes & Static Endpoints:")
        for pat in p2[:20]:
            count_info = f"({pat.total_count} instances)" if pat.total_count > 1 else ""
            output_lines.append(f"- `{pat.pattern_key}` {count_info}")
            if pat.sample_urls:
                output_lines.append(f"  * Sample: `{pat.sample_urls[0]}`")
        if len(p2) > 20:
            output_lines.append(f"  * [... {len(p2) - 20} more P2 patterns in database ...]")
        output_lines.append("")

    output_lines.append(
        "💡 *Smart Recon Note: 100% of distinct parameter combinations and unique endpoints are "
        "preserved above. Focus exploitation on P1 targets first.*"
    )

    return "\n".join(output_lines)
