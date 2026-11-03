"""Agent tool for triaging, compressing, and prioritizing raw reconnaissance outputs."""

from __future__ import annotations

import contextlib
import json
import logging
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from pentesin.recon.compressor import compress_recon_output
from pentesin.tools.nullish import clean_optional


logger = logging.getLogger(__name__)


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

    return result["summary"]


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
