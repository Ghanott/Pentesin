"""``xray`` — run the Chaitin Xray scanner against one authorized live target.

Xray runs inside the sandbox (see ``containers/Dockerfile``). This tool is the
only supported way to drive it: the target is validated against the run's own
authorized scope first, and the process is spawned with an argv list, so no
model-supplied string ever reaches a shell.

Scope is enforced here and nowhere else. The sandbox still has a shell, so an
agent that ignores this tool can call ``xray`` directly; treating this wrapper
as a security boundary would be wrong. It exists to keep the common path
correct, bounded, and auditable.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool


if TYPE_CHECKING:
    from agents.sandbox.session.base_sandbox_session import BaseSandboxSession

logger = logging.getLogger(__name__)

XRAY_BINARY = "xray"
_RESULTS_DIR = "/tmp"  # noqa: S108 - isolated sandbox temp output only
_DEFAULT_TIMEOUT_S = 1800.0
_MAX_TIMEOUT_S = 7200.0
_TERMS_ACK_ENV = "PENTESIN_XRAY_TERMS_ACCEPTED"

# Xray's documented detection-module keys (its README's "Detection Modules"
# table). Free-form would let a caller pass something xray silently ignores, so
# the set is closed and spelled exactly as xray documents it. Callers must
# explicitly select checks relevant to the recon candidate.
_ALLOWED_PLUGINS: frozenset[str] = frozenset(
    {
        "baseline",
        "brute-force",
        "cmd-injection",
        "crlf-injection",
        "dirscan",
        "fastjson",
        "jsonp",
        "path-traversal",
        "phantasm",
        "redirect",
        "shiro",
        "sqldet",
        "ssrf",
        "struts",
        "thinkphp",
        "upload",
        "xss",
        "xstream",
        "xxe",
    }
)

ScanMode = Literal["url"]


def _ctx_session(ctx: RunContextWrapper) -> BaseSandboxSession | None:
    inner: dict[str, Any] = ctx.context if isinstance(ctx.context, dict) else {}
    session = inner.get("sandbox_session")
    return session if session is not None else None


def _authorized_hosts(scan_targets: list[str]) -> set[tuple[str, str | None, int | None]]:
    """(host, scheme, effective_port) triples explicitly present in scan scope."""
    hosts: set[tuple[str, str | None, int | None]] = set()
    for target in scan_targets or []:
        raw = str(target or "").strip()
        if not raw:
            continue
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = (parsed.hostname or "").rstrip(".").lower()
        if not host:
            continue
        scheme = parsed.scheme.lower() or None
        port = parsed.port
        if port is None and scheme in ("http", "https"):
            port = 80 if scheme == "http" else 443
        hosts.add((host, scheme, port))
    return hosts


def _effective_port(parsed: Any) -> int | None:
    if parsed.port is not None:
        return parsed.port
    return {"http": 80, "https": 443}.get(parsed.scheme.lower())


def _scope_config(url: str) -> str:
    """Build Xray config with a single-host fence, redirect ban, and low rate."""
    parsed = urlsplit(url)
    host = json.dumps(parsed.hostname or "")
    port = _effective_port(parsed)
    return (
        "parallel: 5\n"
        "http:\n"
        "  max_redirect: 0\n"
        "  max_qps: 10\n"
        "basic-crawler:\n"
        "  max_depth: 3\n"
        "  max_count_of_links: 500\n"
        "  restriction:\n"
        f"    hostname_allowed: [{host}]\n"
        f"    port_allowed: [{port}]\n"
        ""
    )


def _xray_scan_argv(
    url: str,
    mode: ScanMode,
    plugins: list[str] | None,
    json_output: str,
    config_path: str,
) -> list[str]:
    """Xray CLI options put --config before the subcommand."""
    scan_argv = build_argv(url=url, mode=mode, plugins=plugins, json_output=json_output)
    return [XRAY_BINARY, "--config", config_path, *scan_argv[1:]]


def _validate_target(  # noqa: PLR0911
    target: str, scan_targets: list[str]
) -> tuple[str | None, str | None]:
    """Return ``(url, error)``. Only a target the scan already authorizes passes."""
    raw = (target or "").strip()
    if not raw:
        return None, "target is required - pass the in-scope URL to scan"

    if not raw.startswith(("http://", "https://")):
        return None, (
            f"target must be an absolute http(s) URL, got {raw!r}. "
            "Xray scans a live service, not a host or a path."
        )

    parsed = urlsplit(raw)
    if parsed.username or parsed.password:
        return None, "target must not carry credentials in the URL"
    if parsed.fragment:
        return None, "target must not contain a URL fragment; pass the exact recon URL and query"

    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return None, f"target {raw!r} has no host"

    authorized = _authorized_hosts(scan_targets)
    if not authorized:
        return None, (
            "this run has no authorized live target to compare against; "
            "start the scan with --target so scope is known"
        )

    port = _effective_port(parsed)
    if any(
        known_host == host
        and (known_scheme is None or known_scheme == parsed.scheme.lower())
        and (known_port is None or known_port == port)
        for known_host, known_scheme, known_port in authorized
    ):
        return raw, None

    same_host = {
        (known_scheme, known_port)
        for known_host, known_scheme, known_port in authorized
        if known_host == host
    }
    if same_host:
        allowed = ", ".join(
            f"{scheme or '*'}:{known_port if known_port is not None else '*'}"
            for scheme, known_port in sorted(
                same_host, key=lambda item: (item[0] or "", item[1] or 0)
            )
        )
        return None, f"scheme/port for {host} is out of scope; authorized: {allowed}"

    known = ", ".join(sorted({known_host for known_host, _, _ in authorized}))
    return None, f"{host} is out of scope for this run. Authorized hosts: {known}"


def _validate_plugins(plugins: list[str] | None) -> tuple[list[str] | None, str | None]:
    if not plugins:
        return None, (
            "plugins is required: select checks relevant to the recon candidate, e.g. ['xss']"
        )

    requested = [str(p).strip().lower() for p in plugins if str(p).strip()]
    if not requested:
        return None, "plugins must include at least one relevant check"
    unknown = sorted(set(requested) - _ALLOWED_PLUGINS)
    if unknown:
        return None, (
            f"unknown xray plugin(s): {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(_ALLOWED_PLUGINS))}"
        )
    return requested, None


def _validate_timeout(timeout_s: Any) -> tuple[float | None, str | None]:
    if timeout_s is None:
        return _DEFAULT_TIMEOUT_S, None
    try:
        value = float(timeout_s)
    except (TypeError, ValueError):
        return None, f"timeout_s must be a number, got {timeout_s!r}"
    if value <= 0:
        return None, "timeout_s must be positive"
    if value > _MAX_TIMEOUT_S:
        return None, f"timeout_s must be at most {int(_MAX_TIMEOUT_S)} seconds"
    return value, None


def build_argv(
    *,
    url: str,
    mode: ScanMode,
    plugins: list[str] | None,
    json_output: str,
) -> list[str]:
    """The exact process argv. Kept separate so it is testable without a sandbox."""
    if mode != "url":
        raise ValueError("Xray only supports targeted URL testing; crawling is disabled")
    selected, error = _validate_plugins(plugins)
    if error:
        raise ValueError(error)
    argv = [XRAY_BINARY, "webscan", "--url", url, "--plugins", ",".join(selected or [])]
    argv += ["--json-output", json_output]
    return argv


def _parse_findings(raw: str) -> tuple[list[dict[str, Any]], str | None]:
    """Normalize Xray's JSON array; tolerate newline-delimited output too."""
    text = (raw or "").strip()
    if not text:
        return [], None

    malformed = 0
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        records: list[Any] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            records.extend(record if isinstance(record, list) else [record])
    else:
        records = document if isinstance(document, list) else [document]

    findings: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            malformed += 1
            continue
        detail = record.get("detail") or {}
        target = record.get("target") or {}
        if not isinstance(detail, dict):
            detail = {}
        if not isinstance(target, dict):
            target = {}
        findings.append(
            {
                "plugin": record.get("plugin"),
                "title": detail.get("title") or record.get("plugin"),
                "severity": "unknown",
                "url": detail.get("addr") or detail.get("url") or target.get("url"),
                "created_at": record.get("create_time"),
                "vuln_class": record.get("vuln_class"),
                "evidence": detail.get("snapshot"),
                "payload": detail.get("payload"),
            }
        )

    warning = (
        f"{malformed} output record(s) were not valid JSON findings and were skipped; "
        "the scanner's output format may have changed."
        if malformed
        else None
    )
    return findings, warning


async def _run(
    session: BaseSandboxSession,
    argv: list[str],
    timeout: float,
) -> tuple[str, str, int]:
    result = await session.exec(*argv, timeout=timeout, shell=False)
    stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
    stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
    return stdout, stderr, result.exit_code


async def _read_text(session: BaseSandboxSession, path: str) -> str | None:
    try:
        handle = await session.read(Path(path))
    except FileNotFoundError:
        return None
    try:
        data = handle.read()
    finally:
        with contextlib.suppress(Exception):
            handle.close()
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)


async def _xray_scan_impl(  # noqa: PLR0912, PLR0911, PLR0915
    ctx: RunContextWrapper,
    target: str,
    mode: ScanMode = "url",
    plugins: list[str] | None = None,
    timeout_s: float | None = None,
    bypass_403: bool = False,
) -> str:
    """Implementation of the ``xray_scan`` tool; see the wrapper for the contract.

    Args:
        target: Exact in-scope URL discovered during recon, including its path
            and query parameters. No credentials or fragments.
        mode: Only ``url`` is supported. Crawling and spidering are disabled.
        plugins: Explicit nonempty checks selected for this recon candidate,
            e.g. ``["xss"]`` for a reflected search parameter or ``["sqldet"]``
            for a suspected SQL-backed input. Unknown names are rejected.
        timeout_s: Wall-clock limit for the scan, default 1800, max 7200.
        bypass_403: Also test the target with path and header variants for a
            reachability bypass - useful when the target answers 403 and you
            need to know whether the route is truly closed. Off by default: it
            sends materially more requests. Findings it produces are labelled
            with ``403-bypass`` so they are never confused with a plugin result.

    Returns:
        JSON: ``success``, ``target``, ``argv``, plus ``findings`` and a
        ``count``/``by_severity`` summary, or ``error`` when the target was
        refused or the scan could not complete.
    """
    scan_targets = (
        ctx.context.get("scan_targets") if isinstance(ctx.context, dict) else None
    ) or []

    url, error = _validate_target(target, scan_targets)
    if error:
        return json.dumps({"success": False, "error": error, "target": target})

    if os.getenv(_TERMS_ACK_ENV, "0").lower() not in {"1", "true", "yes"}:
        return json.dumps(
            {
                "success": False,
                "error": (
                    "Xray is disabled until the operator accepts its license and disclaimer. "
                    f"After reviewing https://github.com/chaitin/xray/blob/master/LICENSE.md "
                    f"and https://github.com/chaitin/xray/blob/master/Disclaimer.md, set "
                    f"integrations.xray_terms_accepted=true in pentesin config or "
                    f"{_TERMS_ACK_ENV}=true in the host environment."
                ),
            }
        )

    session = _ctx_session(ctx)
    if session is None:
        return json.dumps({"success": False, "error": "no sandbox session is attached to this run"})

    if mode != "url":
        return json.dumps({
            "success": False,
            "error": "Xray crawling is disabled; test the exact recon URL with mode='url'",
        })
    chosen_plugins, error = _validate_plugins(plugins)
    if error:
        return json.dumps({"success": False, "error": error, "target": target})

    timeout, error = _validate_timeout(timeout_s)
    if error:
        return json.dumps({"success": False, "error": error, "target": target})
    deadline = time.monotonic() + timeout

    token = uuid.uuid4().hex[:12]
    output_dir = f"{_RESULTS_DIR}/xray-{token}"
    output_path = f"{output_dir}/report.json"
    config_path = f"{output_dir}/config.yaml"
    try:
        await session.mkdir(output_dir, parents=True)
        await session.write(
            Path(config_path),
            io.BytesIO(_scope_config(url).encode("utf-8")),
        )
    except Exception as exc:  # noqa: BLE001 - fail before launching a scan
        with contextlib.suppress(Exception):
            await session.rm(output_dir, recursive=True)
        return json.dumps(
            {
                "success": False,
                "target": url,
                "error": f"cannot prepare Xray scan files: {exc}",
            }
        )
    argv = _xray_scan_argv(
        url=url,
        mode=mode,
        plugins=chosen_plugins,
        json_output=output_path,
        config_path=config_path,
    )

    logger.info("xray_scan %s mode=%s plugins=%s", url, mode, chosen_plugins or "default")

    try:
        _, stderr, exit_code = await _run(session, argv, timeout)
    except TimeoutError:
        with contextlib.suppress(Exception):
            await session.rm(output_dir, recursive=True)
        return json.dumps(
            {
                "success": False,
                "target": url,
                "argv": argv,
                "error": f"xray exceeded {int(timeout)}s and was stopped. "
                "Select fewer relevant plugins or raise timeout_s.",
            }
        )
    except Exception as exc:  # scanner failures are model-visible results
        logger.debug("xray_scan failed to start", exc_info=True)
        with contextlib.suppress(Exception):
            await session.rm(output_dir, recursive=True)
        return json.dumps(
            {
                "success": False,
                "target": url,
                "argv": argv,
                "error": f"could not run {XRAY_BINARY}: {exc}. "
                "The sandbox image may need rebuilding.",
            }
        )

    try:
        raw = await _read_text(session, output_path)
    except Exception as exc:  # noqa: BLE001 - read errors must not masquerade as zero findings
        return json.dumps(
            {
                "success": False,
                "target": url,
                "argv": argv,
                "exit_code": exit_code,
                "error": f"xray completed but its JSON report could not be read: {exc}",
            }
        )
    finally:
        with contextlib.suppress(Exception):
            await session.rm(output_dir, recursive=True)

    if raw is None:
        findings, warning = [], None
    else:
        findings, warning = _parse_findings(raw)

    bypass_used: list[dict[str, Any]] = []
    if bypass_403:
        remaining = max(0.0, deadline - time.monotonic())
        if remaining > 0:
            bypass_used = await _probe_403_bypass(session, url, remaining)
            findings.extend(bypass_used)
        else:
            warning = (
                (warning + " ") if warning else ""
            ) + "403-bypass probes skipped because the scan exhausted timeout_s."

    by_severity: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1

    result: dict[str, Any] = {
        "success": True,
        "target": url,
        "argv": argv,
        "exit_code": exit_code,
        "count": len(findings),
        "by_severity": by_severity,
        "severity_note": (
            "Xray JSON has no normalized severity field; severity is 'unknown' "
            "until each candidate is manually validated and calibrated."
            if findings and by_severity == {"unknown": len(findings)}
            else None
        ),
        "findings": findings,
        "output_path": output_path,
    }
    if warning:
        result["warning"] = warning
    if bypass_used:
        result["bypass_403_probes"] = len(bypass_used)
    if exit_code != 0 and not findings:
        result["stderr_tail"] = stderr[-2000:]
    elif not findings:
        result["note"] = (
            "xray reported no findings. That means its plugins reached nothing "
            "at this candidate URL - not that the target is clean. Check the selected "
            "plugins and request reachability before closing this surface."
        )
    return json.dumps(result)


# Header and path variants that a misconfigured proxy, WAF rule, or origin
# routing can mistake for a trusted caller. Each entry is (label, extra argv
# passed to curl). Only added when the caller asks for bypass_403.
_BYPASS_PROBES: tuple[tuple[str, list[str]], ...] = (
    ("X-Forwarded-For:127.0.0.1", ["-H", "X-Forwarded-For: 127.0.0.1"]),
    ("X-Originating-IP:127.0.0.1", ["-H", "X-Originating-IP: 127.0.0.1"]),
    ("X-Remote-IP:127.0.0.1", ["-H", "X-Remote-IP: 127.0.0.1"]),
    ("X-Client-IP:127.0.0.1", ["-H", "X-Client-IP: 127.0.0.1"]),
    ("X-Real-IP:127.0.0.1", ["-H", "X-Real-IP: 127.0.0.1"]),
    ("X-Forwarded-Host:localhost", ["-H", "X-Forwarded-Host: localhost"]),
    ("X-Original-URL:/", ["-H", "X-Original-URL: /"]),
    ("X-Rewrite-URL:/", ["-H", "X-Rewrite-URL: /"]),
    ("Referer:target", []),
    ("path:/.", []),
    ("path://", []),
    ("path:/%2e/", []),
    ("path:..;/", []),
)

# Path variants need the URL suffix appended; header-only probes use the URL as-is.
_PATH_SUFFIX_PROBES = frozenset({"path:/.", "path://", "path:/%2e/", "path:..;/"})


async def _probe_403_bypass(
    session: BaseSandboxSession, url: str, timeout: float
) -> list[dict[str, Any]]:
    """Reachability probes for a 403 response, reported as labelled findings.

    This answers one question: does the route answer *something other than 403*
    when the request is shaped differently? A 200 here is a reachability signal
    to investigate, not proof of a vulnerability - the body still has to be read
    to know what came back.
    """
    findings: list[dict[str, Any]] = []
    deadline = asyncio.get_running_loop().time() + timeout

    # Do not manufacture a "403 bypass" on a route that was not 403 to begin
    # with. This baseline request consumes the same bounded budget as probes.
    baseline_argv = [
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        str(max(1, int(min(20, timeout)))),
        "-k",
        url,
    ]
    try:
        baseline_result = await session.exec(*baseline_argv, timeout=min(timeout, 20), shell=False)
    except Exception:  # noqa: BLE001 - a failed baseline cannot establish 403
        return findings
    baseline_code = (baseline_result.stdout or b"").decode("utf-8", errors="replace").strip()
    if baseline_code != "403":
        return findings

    for label, base_headers in _BYPASS_PROBES:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            logger.warning("403 bypass probe budget exhausted for %s", url)
            break
        probe_url = url
        headers = base_headers
        if label in _PATH_SUFFIX_PROBES:
            probe_url = url.rstrip("/") + label.split(":", 1)[1]
        elif label == "Referer:target":
            headers = ["-H", f"Referer: {url}"]

        argv = [
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            str(max(1, int(min(20, remaining)))),
            "-k",
            *headers,
            probe_url,
        ]
        try:
            result = await session.exec(*argv, timeout=min(remaining, 20), shell=False)
        except Exception:  # a failed probe is not a finding
            logger.debug("403 bypass probe %s failed", label, exc_info=True)
            continue

        code = (result.stdout or b"").decode("utf-8", errors="replace").strip()
        if code and code not in ("403", "000"):
            findings.append(
                {
                    "plugin": "403-bypass",
                    "title": f"{label} returned {code}",
                    "severity": "info",
                    "url": probe_url,
                    "probe": label,
                    "status_code": code,
                    "note": (
                        "Reachability signal only - the route answered "
                        f"{code} instead of 403 for this request shape. Read the "
                        "response body to determine what was actually returned "
                        "before reporting it."
                    ),
                }
            )

    return findings


@function_tool(timeout=7260)
async def xray_scan(
    ctx: RunContextWrapper,
    target: str,
    mode: ScanMode = "url",
    plugins: list[str] | None = None,
    timeout_s: float | None = None,
    bypass_403: bool = False,
) -> str:
    """Run the Chaitin Xray scanner against one in-scope live target.

    Use only after recon identifies a specific URL/path/parameter with a plausible
    vulnerability supported by an Xray plugin. Preserve the candidate URL and
    query exactly and choose only relevant plugins. This tool never crawls or
    spiders the site. The URL must belong to the run's authorized scope.

    It is a scanner, not an oracle: it proves what its plugins can reach
    unauthenticated. Anything behind a login, a multi-step flow, or a payload
    xray does not carry still has to be tested by hand.

    Args:
        target: Exact in-scope URL discovered during recon, including its path
            and query parameters. No credentials or fragments.
        mode: Only ``url`` is supported. Crawling and spidering are disabled.
        plugins: Explicit nonempty checks selected for this recon candidate,
            e.g. ``["xss"]`` for a reflected search parameter or ``["sqldet"]``
            for a suspected SQL-backed input. Unknown names are rejected.
        timeout_s: Wall-clock limit for the scan, default 1800, max 7200.
        bypass_403: Also test the target with path and header variants for a
            reachability bypass - useful when the target answers 403 and you
            need to know whether the route is truly closed. Off by default: it
            sends materially more requests. Findings it produces are labelled
            with ``403-bypass`` so they are never confused with a plugin result.

    Returns:
        JSON: ``success``, ``target``, ``argv``, plus ``findings`` and a
        ``count``/``by_severity`` summary, or ``error`` when the target was
        refused or the scan could not complete.
    """
    return await _xray_scan_impl(
        ctx,
        target,
        mode=mode,
        plugins=plugins,
        timeout_s=timeout_s,
        bypass_403=bypass_403,
    )


__all__ = ["build_argv", "xray_scan"]
