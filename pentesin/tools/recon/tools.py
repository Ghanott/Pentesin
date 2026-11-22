"""Agent tool for triaging, compressing, and prioritizing raw reconnaissance outputs."""

from __future__ import annotations

import contextlib
import io
import json
import logging
import uuid
from pathlib import Path
from typing import Any, Literal

from agents import RunContextWrapper, function_tool

from pentesin.recon.compressor import compress_recon_output
from pentesin.tools.nullish import clean_optional
from pentesin.tools.xray.tools import _validate_target


logger = logging.getLogger(__name__)

_API_RECON_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "recon" / "scripts"
_SANDBOX_SCRIPT_ROOT = "/workspace/.pentesin-scripts/api-recon"
_API_RECON_SCRIPT_NAMES = ("harvest_static.py", "extract_route_map.py", "spider_mpa.py")


async def _read_sandbox_file(session: Any, path_str: str) -> str | None:
    """Read a text file from the sandbox container."""
    if session is None:
        return None
    try:
        handle = await session.read(Path(path_str))
    except (FileNotFoundError, OSError):
        return None
    try:
        data = handle.read()
    finally:
        with contextlib.suppress(Exception):
            handle.close()
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)


def _triage_recon_impl(
    *,
    raw_data: str | None = None,
    file_content: str | None = None,
    sample_limit: int = 2,
) -> dict[str, Any]:
    text = clean_optional(raw_data) or clean_optional(file_content)
    if not text:
        return {
            "success": False,
            "error": "Provide either 'raw_data' (string of URLs/logs) or 'file_path' to triage.",
        }

    summary = compress_recon_output(text, sample_limit=sample_limit)
    return {
        "success": True,
        "summary": summary,
        "message": "Recon output triaged and compressed successfully.",
    }


async def _triage_recon_data_async(
    ctx: RunContextWrapper,
    raw_data: str | None = None,
    file_path: str | None = None,
    sample_limit: int = 2,
) -> str:
    clean_data = clean_optional(raw_data)
    clean_path = clean_optional(file_path)

    file_content: str | None = None
    if clean_path:
        session = ctx.context.get("sandbox_session") if isinstance(ctx.context, dict) else None
        file_content = await _read_sandbox_file(session, clean_path)
        if file_content is None and not clean_data:
            return json.dumps(
                {
                    "success": False,
                    "error": f"Could not read file at '{clean_path}' in the sandbox.",
                }
            )

    result = _triage_recon_impl(
        raw_data=clean_data,
        file_content=file_content,
        sample_limit=sample_limit,
    )

    if not result.get("success"):
        return json.dumps(result)

    return str(result["summary"])


@function_tool(timeout=30)
async def triage_recon_data(
    ctx: RunContextWrapper,
    raw_data: str | None = None,
    file_path: str | None = None,
    sample_limit: int = 2,
) -> str:
    """Triage, deduplicate, and prioritize raw crawler/recon outputs (Katana, ffuf, httpx).

    Reduces hundreds or thousands of repetitive URLs into unique parameterized patterns
    and ranks them into P1 (High-Priority: parameters, auth, APIs, uploads) and P2
    (Standard) to avoid context exhaustion while preserving 100% of distinct attack surfaces.

    Args:
        ctx: Run context wrapper.
        raw_data: Optional raw string output from a recon tool (e.g. newline-delimited URLs).
        file_path: Optional path to recon output file in sandbox (e.g. '/workspace/katana.txt').
        sample_limit: Maximum sample URLs to retain per distinct pattern (default: 2).
    """
    return await _triage_recon_data_async(
        ctx=ctx,
        raw_data=raw_data,
        file_path=file_path,
        sample_limit=sample_limit,
    )


def _read_lines(text: str | None) -> list[str]:
    if not text:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


async def _stage_api_recon_scripts(session: Any) -> str | None:
    try:
        await session.mkdir(_SANDBOX_SCRIPT_ROOT, parents=True)
        for script_name in _API_RECON_SCRIPT_NAMES:
            src_path = _API_RECON_SCRIPTS_DIR / script_name
            payload = src_path.read_bytes()
            await session.write(Path(f"{_SANDBOX_SCRIPT_ROOT}/{script_name}"), io.BytesIO(payload))
    except Exception as exc:  # noqa: BLE001
        return f"failed to stage api-recon scripts into sandbox: {exc}"
    return None


async def _run_harvesters(
    *,
    session: Any,
    validated_url: str,
    run_dir: str,
    mode: Literal["auto", "spa", "mpa"],
    cookie: str | None,
    max_pages: int,
    depth: int,
) -> tuple[list[str], list[str], list[str]]:
    if mode in {"auto", "spa"}:
        await session.exec(
            "python3",
            f"{_SANDBOX_SCRIPT_ROOT}/harvest_static.py",
            validated_url,
            run_dir,
            timeout=120,
            shell=False,
        )
        await session.exec(
            "python3",
            f"{_SANDBOX_SCRIPT_ROOT}/extract_route_map.py",
            f"{run_dir}/js",
            run_dir,
            timeout=30,
            shell=False,
        )

    api_static = _read_lines(await _read_sandbox_file(session, f"{run_dir}/api_static.txt"))
    paths_other = _read_lines(await _read_sandbox_file(session, f"{run_dir}/paths_other.txt"))
    routes = _read_lines(await _read_sandbox_file(session, f"{run_dir}/routes.txt"))

    if mode == "mpa" or (mode == "auto" and (len(api_static) + len(routes)) < 3):
        mpa_argv = [
            "python3",
            f"{_SANDBOX_SCRIPT_ROOT}/spider_mpa.py",
            validated_url,
            run_dir,
            "--max",
            str(max(10, min(int(max_pages), 300))),
            "--depth",
            str(max(1, min(int(depth), 6))),
        ]
        clean_cookie = clean_optional(cookie)
        if clean_cookie:
            mpa_argv.extend(["--cookie", clean_cookie])
        await session.exec(*mpa_argv, timeout=120, shell=False)

    return api_static, paths_other, routes


def _format_harvest_summary(
    *,
    validated_url: str,
    mode: str,
    run_dir: str,
    api_static: list[str],
    routes: list[str],
    paths_other: list[str],
    forms: list[str],
    api_inline: list[str],
    links: list[str],
    route_map_raw: str | None,
) -> str:
    sections: list[str] = [
        "### [ARTEX API Surface Harvest]",
        f"- **Target:** `{validated_url}` (mode=`{mode}`)",
        f"- **Saved Workspace Dir:** `{run_dir}`",
        (
            f"- **Counts:** SPA API=`{len(api_static)}`, Routes=`{len(routes)}`, "
            f"Other Paths=`{len(paths_other)}`, MPA Forms=`{len(forms)}`, "
            f"Inline AJAX=`{len(api_inline)}`, Pages=`{len(links)}`"
        ),
    ]
    section_items = [
        ("SPA API Endpoints (`api_static.txt`):", api_static, 80),
        ("Inline AJAX Endpoints (`api_inline.txt`):", api_inline, 50),
        ("HTML Forms (`forms.txt`):", forms, 50),
        ("Frontend Routes (`routes.txt`):", routes, 50),
    ]
    for title, items, cap in section_items:
        if items:
            sections.append(f"\n#### {title}")
            sections.extend(f"- `{item}`" for item in items[:cap])
    if route_map_raw:
        sections.append(
            f"\n- **route_map.json:** `{len(route_map_raw)}` bytes captured "
            f"in `{run_dir}/route_map.json`"
        )
    if paths_other and not api_static:
        sections.append("\n#### Other Paths (`paths_other.txt`):")
        sections.extend(f"- `{p}`" for p in paths_other[:40])
    if links:
        triaged = compress_recon_output("\n".join(links[:300]), sample_limit=2)
        if triaged:
            sections.append(f"\n{triaged}")
    return "\n".join(sections)


async def _harvest_api_surface_async(
    ctx: RunContextWrapper,
    target_url: str,
    mode: Literal["auto", "spa", "mpa"] = "auto",
    cookie: str | None = None,
    max_pages: int = 120,
    depth: int = 4,
) -> str:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    scan_targets = inner.get("scan_targets") or []
    validated_url, error = _validate_target(target_url, scan_targets)
    if error or validated_url is None:
        return json.dumps(
            {"success": False, "error": error or "invalid target", "target": target_url}
        )

    session = inner.get("sandbox_session")
    if session is None:
        return json.dumps({"success": False, "error": "no sandbox session attached to this run"})

    if mode not in {"auto", "spa", "mpa"}:
        return json.dumps(
            {"success": False, "error": f"invalid mode {mode!r}; use auto, spa, or mpa"}
        )

    stage_err = await _stage_api_recon_scripts(session)
    if stage_err:
        return json.dumps({"success": False, "error": stage_err, "target": validated_url})

    run_dir = f"/workspace/api-recon-{uuid.uuid4().hex[:8]}"
    await session.mkdir(run_dir, parents=True)

    api_static, paths_other, routes = await _run_harvesters(
        session=session,
        validated_url=validated_url,
        run_dir=run_dir,
        mode=mode,
        cookie=cookie,
        max_pages=max_pages,
        depth=depth,
    )
    forms = _read_lines(await _read_sandbox_file(session, f"{run_dir}/forms.txt"))
    api_inline = _read_lines(await _read_sandbox_file(session, f"{run_dir}/api_inline.txt"))
    links = _read_lines(await _read_sandbox_file(session, f"{run_dir}/links.txt"))
    route_map_raw = await _read_sandbox_file(session, f"{run_dir}/route_map.json")

    return _format_harvest_summary(
        validated_url=validated_url,
        mode=mode,
        run_dir=run_dir,
        api_static=api_static,
        routes=routes,
        paths_other=paths_other,
        forms=forms,
        api_inline=api_inline,
        links=links,
        route_map_raw=route_map_raw,
    )


@function_tool(timeout=180)
async def harvest_api_surface(
    ctx: RunContextWrapper,
    target_url: str,
    mode: Literal["auto", "spa", "mpa"] = "auto",
    cookie: str | None = None,
    max_pages: int = 120,
    depth: int = 4,
) -> str:
    """Harvest SPA JS bundle endpoints/chunk manifests and MPA forms/AJAX routes inside the sandbox.

    Adapted from ARTEX's api-recon toolchain (`harvest_static.py`, `extract_route_map.py`,
    `spider_mpa.py`). Safely scope-checked against authorized scan targets before running.

    Args:
        ctx: Run context wrapper.
        target_url: Absolute in-scope http(s) URL to harvest (e.g. 'https://app.example.com').
        mode: 'auto' (SPA JS harvest with MPA fallback if sparse), 'spa', or 'mpa'.
        cookie: Optional Cookie header value for authenticated MPA crawling.
        max_pages: Page cap for MPA crawl (10-300, default 120).
        depth: Max crawl depth for MPA mode (1-6, default 4).
    """
    return await _harvest_api_surface_async(
        ctx=ctx,
        target_url=target_url,
        mode=mode,
        cookie=cookie,
        max_pages=max_pages,
        depth=depth,
    )
