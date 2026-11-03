"""Tests for Smart Recon URL filtering, pattern deduplication, and output compression."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from pentesin.agents.prompt import render_scope_prompt
from pentesin.interface.cli_args import parse_arguments
from pentesin.recon.compressor import (
    compress_recon_output,
    deduplicate_url_patterns,
    filter_binary_extensions,
    rank_recon_endpoints,
)


if TYPE_CHECKING:
    import pytest


def test_filter_binary_extensions() -> None:
    urls = [
        "https://example.com/index.html",
        "https://example.com/assets/font.woff2",
        "https://example.com/static/favicon.ico",
        "https://example.com/video/intro.mp4",
        "https://example.com/images/logo.svg",  # SVG is sensitive/exploitable (XSS)
        "https://example.com/api/v1/config.json",
        "https://example.com/.env",
    ]
    kept, dropped = filter_binary_extensions(urls)

    assert "https://example.com/assets/font.woff2" in dropped
    assert "https://example.com/static/favicon.ico" in dropped
    assert "https://example.com/video/intro.mp4" in dropped

    assert "https://example.com/index.html" in kept
    assert "https://example.com/images/logo.svg" in kept
    assert "https://example.com/api/v1/config.json" in kept
    assert "https://example.com/.env" in kept
    assert len(dropped) == 3
    assert len(kept) == 4


def test_deduplicate_url_patterns() -> None:
    # 50 repetitive URLs with the same parameter pattern
    urls = [f"https://example.com/products/item?id={i}&category=books" for i in range(1, 51)]
    # Plus a different endpoint
    urls.append("https://example.com/login")

    res = deduplicate_url_patterns(urls, sample_limit=2)

    assert res["total_raw"] == 51
    assert res["total_unique_patterns"] == 2
    patterns = res["patterns"]

    product_pattern = next(p for p in patterns if "products/item" in p.pattern_key)
    assert product_pattern.total_count == 50
    assert len(product_pattern.sample_urls) == 2
    assert product_pattern.is_parameterized is True
    assert product_pattern.is_high_priority is True


def test_path_id_normalization() -> None:
    urls = [
        "https://example.com/api/users/123/orders",
        "https://example.com/api/users/456/orders",
        "https://example.com/api/users/789/orders",
    ]
    res = deduplicate_url_patterns(urls, sample_limit=2)
    assert res["total_unique_patterns"] == 1
    pattern = res["patterns"][0]
    assert "{id}" in pattern.normalized_path
    assert pattern.total_count == 3


def test_rank_recon_endpoints() -> None:
    urls = [
        "https://example.com/about-us",
        "https://example.com/contact",
        "https://example.com/api/v1/auth/login",
        "https://example.com/upload",
        "https://example.com/search?q=test",
    ]
    res = deduplicate_url_patterns(urls)
    ranked = rank_recon_endpoints(res["patterns"])

    p1_keys = [p.pattern_key for p in ranked["p1_high_priority"]]
    p2_keys = [p.pattern_key for p in ranked["p2_standard"]]

    assert any("login" in k for k in p1_keys)
    assert any("upload" in k for k in p1_keys)
    assert any("search" in k for k in p1_keys)
    assert any("about-us" in k for k in p2_keys)


def test_compress_recon_output_plain_text() -> None:
    raw_lines = (
        "https://example.com/api/users/1?page=1\n"
        "https://example.com/api/users/2?page=1\n"
        "https://example.com/style.css\n"
        "https://example.com/font.woff"
    )
    summary = compress_recon_output(raw_lines)
    assert "[Smart Recon]" in summary
    assert "**Raw URLs Processed:** 4" in summary
    assert "**Filtered Static Binaries:** 1" in summary
    assert "P1: High-Priority" in summary


def test_compress_recon_output_jsonl() -> None:
    jsonl_output = (
        '{"url": "https://example.com/api/v1/items?id=1", "status": 200}\n'
        '{"url": "https://example.com/api/v1/items?id=2", "status": 200}\n'
        '{"url": "https://example.com/logo.png", "status": 200}'
    )
    summary = compress_recon_output(jsonl_output)
    assert "[Smart Recon]" in summary
    assert "**Raw URLs Processed:** 3" in summary
    assert "**Filtered Static Binaries:** 1" in summary
    assert "items?id" in summary


def test_smart_recon_prompt_isolation_when_off() -> None:
    # Prompt with smart_recon False / omitted
    prompt_off = render_scope_prompt({"smart_recon": False})
    prompt_omitted = render_scope_prompt({})

    assert "SMART RECON (active this run)" not in prompt_off
    assert "triage_recon_data" not in prompt_off
    assert "SMART RECON (active this run)" not in prompt_omitted
    assert prompt_off == prompt_omitted


def test_smart_recon_prompt_active_when_on() -> None:
    prompt_on = render_scope_prompt({"smart_recon": True})
    assert "SMART RECON (active this run)" in prompt_on
    assert "triage_recon_data" in prompt_on


def test_smart_recon_cli_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["pentesin", "-t", "https://example.com", "-n"])
    args_default = parse_arguments()
    assert args_default.smart_recon is False

    monkeypatch.setattr(
        sys, "argv", ["pentesin", "-t", "https://example.com", "-n", "--smart-recon"]
    )
    args_flag = parse_arguments()
    assert args_flag.smart_recon is True
