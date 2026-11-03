"""Tests for exploit chaining agent tools."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pentesin.report.state import ReportState, set_global_report_state
from pentesin.tools.chain.tools import (
    _link_impl,
    _suggest_impl,
    link_exploit_chain,
    suggest_exploit_chains,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    return state


def test_tool_registration_properties() -> None:
    assert suggest_exploit_chains.name == "suggest_exploit_chains"
    assert link_exploit_chain.name == "link_exploit_chain"


def test_suggest_exploit_chains_by_type() -> None:
    result = _suggest_impl(
        vuln_type="open_redirect",
        title="Open redirect on /login?return_to=",
        endpoint="https://example.com/login?return_to=https://evil.com",
    )
    assert result["success"] is True
    assert result["count"] >= 1
    assert any("OAuth" in c["title"] for c in result["candidates"])


def test_suggest_exploit_chains_by_finding_id(report_state: ReportState) -> None:
    # File an initial low finding
    report_id = report_state.add_vulnerability_report(
        title="CORS Misconfiguration on /api/user",
        severity="low",
        description="Arbitrary origin reflected with credentials",
        impact="Cross-origin reading if chained",
        target="https://example.com",
        technical_analysis="Tested with Origin: evil.com",
        poc_description="curl command",
        poc_script_code="curl -H 'Origin: evil.com' ...",
        remediation_steps="Restrict allowed origins",
        evidence="HTTP 200 with Access-Control-Allow-Origin: evil.com",
        assumptions="User is logged in",
        counterevidence="none",
        confidence="high",
        severity_change_conditions="Demonstrate PII exfiltration",
        fix_effort="low",
        cvss_breakdown={
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "N",
            "availability": "N",
        },
        endpoint="/api/user",
        cwe="CWE-942",
    )

    result = _suggest_impl(finding_id=report_id)
    assert result["success"] is True
    assert result["count"] >= 1
    candidate_titles = [c["title"] for c in result["candidates"]]
    assert any("CORS" in t for t in candidate_titles)


def test_link_exploit_chain_success(report_state: ReportState) -> None:
    # 1. File primary finding (Low: Open Redirect)
    p_id = report_state.add_vulnerability_report(
        title="Open Redirect on /redirect",
        severity="low",
        description="Unvalidated redirect",
        impact="Phishing",
        target="https://example.com",
        technical_analysis="Location header follows parameter",
        poc_description="Visit URL",
        poc_script_code="curl https://example.com/redirect?to=https://evil.com",
        remediation_steps="Whitelist redirect targets",
        evidence="302 Found",
        assumptions="User clicks link",
        counterevidence="none",
        confidence="high",
        severity_change_conditions="OAuth token exfiltration",
        fix_effort="low",
        cvss_breakdown={
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "N",
            "availability": "N",
        },
        endpoint="/redirect",
        cwe="CWE-601",
    )

    # 2. File secondary finding (Medium: OAuth missing PKCE)
    s_id = report_state.add_vulnerability_report(
        title="OAuth Flow Missing PKCE & Permissive Redirect",
        severity="medium",
        description="OAuth authorization endpoint accepts subdomain redirects",
        impact="Authorization code theft",
        target="https://example.com",
        technical_analysis="Flow proceeds without code_challenge",
        poc_description="Authorize request",
        poc_script_code="GET /oauth/authorize?client_id=1&redirect_uri=...",
        remediation_steps="Enforce strict redirect URI matching and PKCE",
        evidence="Code delivered",
        assumptions="User authorizes",
        counterevidence="none",
        confidence="high",
        severity_change_conditions="Full account takeover",
        fix_effort="medium",
        cvss_breakdown={
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "N",
            "availability": "N",
        },
        endpoint="/oauth/authorize",
        cwe="CWE-287",
    )

    # 3. Link them into an exploit chain
    res = _link_impl(
        primary_finding_id=p_id,
        secondary_finding_ids=[s_id],
        chain_title="Account Takeover via Open Redirect & OAuth Code Theft",
        escalated_severity="critical",
        escalated_impact="Full account takeover without victim credential knowledge",
        combined_poc=(
            "1. Send link with redirect_uri pointed to open redirect\n"
            "2. Capture authorization code\n"
            "3. Exchange for token"
        ),
    )
    assert res["success"] is True
    assert res["escalated_severity"] == "critical"
    assert res["chain_id"] == f"CHAIN-{p_id}"

    # Verify primary finding got updated
    updated_primary = next(
        v for v in report_state.get_existing_vulnerabilities() if v["id"] == p_id
    )
    assert updated_primary["severity"] == "critical"
    assert "[CHAIN]" in updated_primary["title"]
    assert "chain_metadata" in updated_primary
    assert updated_primary["chain_metadata"]["is_chain_root"] is True


def test_link_exploit_chain_missing_findings(report_state: ReportState) -> None:
    res = _link_impl(
        primary_finding_id="NON_EXISTENT_ID",
        secondary_finding_ids=["ALSO_MISSING"],
        chain_title="Invalid Chain",
        escalated_severity="critical",
        escalated_impact="None",
        combined_poc="None",
    )
    assert report_state is not None
    assert res["success"] is False
    assert "not found" in res["error"]
