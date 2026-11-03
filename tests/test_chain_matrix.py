"""Tests for exploit chaining signal matrix and candidate generation."""

from __future__ import annotations

from pentesin.chain.matrix import find_chain_candidates


def test_open_redirect_matches_oauth_chain() -> None:
    sitemap = [
        "https://example.com/login",
        "https://example.com/oauth/authorize?client_id=123",
        "https://example.com/static/bundle.js",
    ]
    candidates = find_chain_candidates(
        vuln_type="open_redirect",
        title="Unvalidated Open Redirect in /redirect?to=",
        sitemap_urls=sitemap,
    )

    assert len(candidates) >= 1
    oauth_chain = next(
        (c for c in candidates if c.chain_id == "chain_open_redirect_oauth_ato"), None
    )
    assert oauth_chain is not None
    assert oauth_chain.escalated_severity == "critical"
    assert "OAuth" in oauth_chain.title
    assert "https://example.com/oauth/authorize?client_id=123" in oauth_chain.matched_target_urls


def test_ssrf_matches_cloud_metadata_chain() -> None:
    candidates = find_chain_candidates(
        cwe="CWE-918",
        title="Blind SSRF on Webhook Endpoint",
        description="Endpoint fetches URL passed in request body",
    )

    assert len(candidates) >= 1
    ssrf_chain = next(
        (c for c in candidates if c.chain_id == "chain_ssrf_cloud_metadata_creds"), None
    )
    assert ssrf_chain is not None
    assert ssrf_chain.escalated_severity == "critical"
    assert "169.254.169.254" in ssrf_chain.actionable_steps[0]


def test_cors_matches_data_exfil_chain() -> None:
    sitemap = [
        "https://example.com/api/v1/user/profile",
        "https://example.com/about",
    ]
    candidates = find_chain_candidates(
        vuln_type="cors_misconfiguration",
        title="CORS Origin Reflection with Credentials",
        sitemap_urls=sitemap,
    )

    assert len(candidates) >= 1
    cors_chain = next((c for c in candidates if c.chain_id == "chain_cors_data_exfil"), None)
    assert cors_chain is not None
    assert cors_chain.escalated_severity == "high"
    assert "https://example.com/api/v1/user/profile" in cors_chain.matched_target_urls


def test_idor_matches_state_tampering_chain() -> None:
    candidates = find_chain_candidates(
        vuln_type="idor",
        title="IDOR on GET /api/v2/orders/123",
        cwe="CWE-639",
    )

    assert len(candidates) >= 1
    idor_chain = next((c for c in candidates if c.chain_id == "chain_idor_state_tampering"), None)
    assert idor_chain is not None
    assert "State Modification" in idor_chain.title


def test_unknown_vulnerability_returns_empty() -> None:
    candidates = find_chain_candidates(
        vuln_type="unknown_bug",
        title="Harmless informational banner",
        cwe="CWE-9999",
    )
    assert candidates == []


def test_candidate_serialization() -> None:
    candidates = find_chain_candidates(vuln_type="open_redirect", title="Open redirect")
    assert len(candidates) >= 1
    serialized = candidates[0].to_dict()
    assert isinstance(serialized, dict)
    assert "chain_id" in serialized
    assert "escalated_severity" in serialized
    assert "actionable_steps" in serialized
