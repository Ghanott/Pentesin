"""Tests for triage_recon_data tool and implementation."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from agents import RunContextWrapper

from pentesin.tools.recon.tools import (
    _triage_recon_data_async,
    _triage_recon_impl,
    triage_recon_data,
)


@pytest.fixture
def mock_ctx() -> RunContextWrapper:
    mock = MagicMock(spec=RunContextWrapper)
    mock.context = {}
    return mock


def test_triage_recon_tool_properties() -> None:
    assert triage_recon_data.name == "triage_recon_data"


def test_triage_recon_impl_empty() -> None:
    res = _triage_recon_impl()
    assert res["success"] is False
    assert "Provide either" in res["error"]


def test_triage_recon_impl_with_raw_data() -> None:
    raw = (
        "https://target.com/items?id=1\n"
        "https://target.com/items?id=2\n"
        "https://target.com/login\n"
        "https://target.com/favicon.ico"
    )
    res = _triage_recon_impl(raw_data=raw)
    assert res["success"] is True
    summary = res["summary"]
    assert "[Smart Recon]" in summary
    assert "**Raw URLs Processed:** 4" in summary
    assert "**Filtered Static Binaries:** 1" in summary


@pytest.mark.asyncio
async def test_triage_recon_data_tool_execution(mock_ctx: RunContextWrapper) -> None:
    raw = "https://target.com/api/v1/user/1\nhttps://target.com/api/v1/user/2"
    result = await _triage_recon_data_async(mock_ctx, raw_data=raw)
    assert "[Smart Recon]" in result
    assert "**Raw URLs Processed:** 2" in result


@pytest.mark.asyncio
async def test_triage_recon_data_missing_file(mock_ctx: RunContextWrapper) -> None:
    mock_session = AsyncMock()
    mock_session.read.side_effect = FileNotFoundError
    mock_ctx.context = {"sandbox_session": mock_session}

    result_raw = await _triage_recon_data_async(mock_ctx, file_path="/workspace/missing.txt")
    result = json.loads(result_raw)
    assert result["success"] is False
    assert "Could not read file" in result["error"]
