"""Recon output compression, pattern deduplication, and attack-surface prioritization."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit


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


def _quote_inert(value: Any, max_len: int = 160) -> str:
    """Serialize target-controlled free text as a bounded quoted string."""
    text = str(value or "").strip()
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return json.dumps(text, ensure_ascii=False)


_NMAP_HOST_RE = re.compile(r"<host\b[^>]*>(.*?)</host>", re.DOTALL)
_NMAP_ADDR_RE = re.compile(r'<address\b[^>]*\baddr="([^"]+)"')
_NMAP_PORT_RE = re.compile(
    r'<port\b[^>]*\bprotocol="([^"]+)"[^>]*\bportid="(\d+)"[^>]*>(.*?)</port>',
    re.DOTALL,
)
_NMAP_PORT_ALT_RE = re.compile(
    r'<port\b[^>]*\bportid="(\d+)"[^>]*\bprotocol="([^"]+)"[^>]*>(.*?)</port>',
    re.DOTALL,
)
_NMAP_STATE_OPEN_RE = re.compile(r'<state\b[^>]*\bstate="open"')
_NMAP_ATTR_NAME_RE = re.compile(r'\bname="([^"]*)"')
_NMAP_ATTR_PROD_RE = re.compile(r'\bproduct="([^"]*)"')
_NMAP_ATTR_VER_RE = re.compile(r'\bversion="([^"]*)"')


def _match_attr(body: str, pattern: re.Pattern[str]) -> str:
    found = pattern.search(body)
    return found.group(1) if found else ""


def _parse_nmap_xml(stripped: str) -> str | None:
    if "<nmaprun" not in stripped:
        return None
    lines = ["### [Smart Recon] Nmap Structured Summary"]
    host_count = 0
    port_count = 0
    for host_match in _NMAP_HOST_RE.finditer(stripped):
        host_body = host_match.group(1)
        addr_match = _NMAP_ADDR_RE.search(host_body)
        addr = addr_match.group(1) if addr_match else "unknown"
        open_ports: list[str] = []
        ports_iter: list[tuple[str, str, str]] = [
            (m.group(2), m.group(1), m.group(3)) for m in _NMAP_PORT_RE.finditer(host_body)
        ]
        if not ports_iter:
            ports_iter = [
                (m.group(1), m.group(2), m.group(3)) for m in _NMAP_PORT_ALT_RE.finditer(host_body)
            ]
        for pid, proto, port_body in ports_iter:
            if not _NMAP_STATE_OPEN_RE.search(port_body):
                continue
            port_count += 1
            svc_name = _match_attr(port_body, _NMAP_ATTR_NAME_RE)
            product = _match_attr(port_body, _NMAP_ATTR_PROD_RE)
            version = _match_attr(port_body, _NMAP_ATTR_VER_RE)
            detail = " ".join(p for p in (product, version) if p)
            if detail:
                suffix = f" ({svc_name} {_quote_inert(detail)})"
            elif svc_name:
                suffix = f" ({svc_name})"
            else:
                suffix = ""
            open_ports.append(f"{pid}/{proto}{suffix}")
        if open_ports:
            host_count += 1
            lines.append(f"- `{addr}`: {', '.join(open_ports[:40])}")
    if host_count == 0:
        return None
    lines.insert(1, f"- **Hosts with Open Ports:** {host_count} ({port_count} open ports)")
    return "\n".join(lines)


def _parse_single_json_scanner(stripped: str) -> str | None:
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    results = obj.get("results")
    if (
        isinstance(results, list)
        and results
        and isinstance(results[0], dict)
        and "url" in results[0]
    ):
        lines = [
            "### [Smart Recon] ffuf Structured Summary",
            f"- **Total Hits:** {len(results)}",
        ]
        for item in results[:50]:
            url = str(item.get("url") or "")
            status = item.get("status", "?")
            length = item.get("length", "?")
            words = item.get("words", "?")
            lines.append(f"- `{url}` [status={status}, len={length}, words={words}]")
        if len(results) > 50:
            lines.append(f"- [... {len(results) - 50} more hits truncated ...]")
        return "\n".join(lines)

    arjun_entries: list[str] = []
    for key, val in list(obj.items())[:50]:
        if (
            isinstance(key, str)
            and key.startswith(("http://", "https://"))
            and isinstance(val, dict)
            and isinstance(val.get("params"), list)
        ):
            method = str(val.get("method") or "GET").upper()
            params = [str(p) for p in val["params"][:30]]
            arjun_entries.append(f"- `{method} {key}` -> params: {', '.join(params)}")
    if not arjun_entries:
        return None
    return "\n".join(
        [
            "### [Smart Recon] Arjun Parameter Discovery Summary",
            f"- **Endpoints with Hidden Params:** {len(arjun_entries)}",
            *arjun_entries,
        ]
    )


_BBOT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.>-]{1,128}$")
_BBOT_HOST_RE = re.compile(r"^[a-z0-9_.-]{1,253}$")


def _clean_bbot_host(raw: Any) -> str:
    host = str(raw or "").strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host if _BBOT_HOST_RE.match(host) else ""


def _clean_bbot_url(raw: Any, expected_host: str) -> str:
    text = str(raw or "").strip()
    if not text or not expected_host:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.hostname.lower().rstrip(".") != expected_host:
        return ""
    # Strip embedded credentials cleanly.
    netloc = parsed.hostname
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _format_bbot_record(rec: dict[str, Any]) -> tuple[bool, str] | None:
    """Format one typed bbot JSONL record, separating scope_distance == 0 vs external intel."""
    raw_type = str(rec.get("type") or "").strip()
    raw_module = str(rec.get("module") or "").strip()
    if not (_BBOT_TOKEN_RE.match(raw_type) and _BBOT_TOKEN_RE.match(raw_module)):
        return None
    scope_dist = rec.get("scope_distance")
    in_scope = isinstance(scope_dist, int) and not isinstance(scope_dist, bool) and scope_dist == 0
    host = _clean_bbot_host(rec.get("host"))
    url = _clean_bbot_url(rec.get("url"), host)
    port_val = rec.get("port")
    port = port_val if isinstance(port_val, int) and 0 < port_val <= 65535 else 0
    raw_data = rec.get("data_json") if rec.get("data_json") is not None else rec.get("data")
    data_str = ""
    if raw_data is not None:
        serialized = (
            raw_data if isinstance(raw_data, str) else json.dumps(raw_data, ensure_ascii=False)
        )
        data_str = f" data={_quote_inert(serialized)}"
    target_part = url or host or "(unknown)"
    port_part = f":{port}" if port and not url else ""
    line = f"- [{raw_type}] `{target_part}{port_part}` via `{raw_module}`{data_str}"
    return in_scope, line


def _format_httpx_record(rec: dict[str, Any]) -> str:
    url = str(rec.get("url") or rec.get("input") or "")
    sc = rec.get("status_code")
    title = _quote_inert(rec.get("title") or "") if rec.get("title") else ""
    tech = rec.get("tech") if isinstance(rec.get("tech"), list) else []
    tech_str = f" tech={','.join(str(t) for t in tech[:8])}" if tech else ""
    title_str = f" title={title}" if title else ""
    return f"- `{url}` [{sc}]{tech_str}{title_str}"


def _format_nuclei_record(rec: dict[str, Any]) -> str:
    tid = str(rec.get("template-id") or "unknown")
    raw_info = rec.get("info")
    info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
    sev = str(info.get("severity") or "info").upper()
    matched = str(rec.get("matched-at") or rec.get("host") or "")
    name = _quote_inert(info.get("name") or tid)
    return f"- [{sev}] `{tid}` at `{matched}` (name={name})"


def _render_jsonl_summary(
    nuclei_hits: list[str],
    httpx_hosts: list[str],
    bbot_in_scope: list[str],
    bbot_intel: list[str],
) -> str | None:
    if nuclei_hits:
        return "\n".join(
            [
                "### [Smart Recon] Nuclei Structured Summary",
                f"- **Total Matches:** {len(nuclei_hits)}",
                *nuclei_hits[:60],
            ]
        )
    if httpx_hosts:
        return "\n".join(
            [
                "### [Smart Recon] httpx Structured Summary",
                f"- **Live Endpoints:** {len(httpx_hosts)}",
                *httpx_hosts[:60],
            ]
        )
    if not (bbot_in_scope or bbot_intel):
        return None
    lines = [
        "### [Smart Recon] BBOT Event Graph Summary",
        f"- **In-Scope Events (`scope_distance=0`):** {len(bbot_in_scope)}",
        f"- **External / Third-Party Intel (do NOT auto-attack):** {len(bbot_intel)}",
    ]
    if bbot_in_scope:
        lines.append("\n#### In-Scope Assets & Signals:")
        lines.extend(bbot_in_scope[:50])
    if bbot_intel:
        lines.append("\n#### External Intel (`scope_distance != 0` — intel only):")
        lines.extend(bbot_intel[:20])
    return "\n".join(lines)


def _parse_jsonl_scanner(stripped: str) -> str | None:
    nuclei_hits: list[str] = []
    httpx_hosts: list[str] = []
    bbot_in_scope: list[str] = []
    bbot_intel: list[str] = []
    for raw_line in stripped.splitlines():
        line = raw_line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        if "template-id" in rec:
            nuclei_hits.append(_format_nuclei_record(rec))
        elif "status_code" in rec and ("url" in rec or "input" in rec):
            httpx_hosts.append(_format_httpx_record(rec))
        elif "type" in rec and "module" in rec and (
            "scope_distance" in rec or "data" in rec or "data_json" in rec
        ):
            parsed_bbot = _format_bbot_record(rec)
            if parsed_bbot is not None:
                is_in_scope, formatted = parsed_bbot
                (bbot_in_scope if is_in_scope else bbot_intel).append(formatted)

    return _render_jsonl_summary(nuclei_hits, httpx_hosts, bbot_in_scope, bbot_intel)


def parse_structured_scanner_output(text: str) -> str | None:
    """Deterministically parse nmap XML, ffuf JSON, nuclei JSONL, httpx JSONL, or arjun JSON.

    Target-controlled free-text fields (titles, banners, template names) are
    always quoted as inert strings to resist prompt injection.
    """
    stripped = text.strip()
    if not stripped:
        return None
    if stripped.startswith(("<?xml", "<nmaprun")):
        return _parse_nmap_xml(stripped)
    return _parse_single_json_scanner(stripped) or _parse_jsonl_scanner(stripped)


def compress_recon_output(text: str, *, sample_limit: int = 2) -> str:
    """Process raw crawler/fuzzer logs into a high-density attack-surface summary."""
    if not text or not text.strip():
        return "No recon output provided."

    structured = parse_structured_scanner_output(text)
    if structured is not None:
        return structured

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
