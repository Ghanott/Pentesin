"""Agent tools for autonomous exploit chaining.

Provides ``suggest_exploit_chains`` to explore potential A -> B -> C escalations
and ``link_exploit_chain`` to combine and upgrade confirmed findings into a single
high-impact exploit chain.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from pentesin.chain.matrix import find_chain_candidates
from pentesin.report.state import get_global_report_state
from pentesin.tools.nullish import clean_optional


logger = logging.getLogger(__name__)

_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def _extract_sitemap_urls(report_state: Any) -> list[str]:
    """Extract known endpoints and URLs from existing report state and coverage."""
    urls: list[str] = []
    if report_state is None:
        return urls

    # Read from existing findings
    for vuln in report_state.get_existing_vulnerabilities():
        ep = vuln.get("endpoint") or vuln.get("target")
        if ep and isinstance(ep, str) and ep not in urls:
            urls.append(ep)

    # Read from coverage state if available
    coverage = getattr(report_state, "coverage", None)
    if isinstance(coverage, dict):
        for ep in coverage:
            if isinstance(ep, str) and ep not in urls:
                urls.append(ep)

    return urls


def _suggest_impl(
    *,
    finding_id: str | None = None,
    vuln_type: str | None = None,
    title: str | None = None,
    endpoint: str | None = None,
) -> dict[str, Any]:
    clean_id = clean_optional(finding_id)
    clean_type = clean_optional(vuln_type)
    clean_title = clean_optional(title)
    clean_endpoint = clean_optional(endpoint)

    report_state = get_global_report_state()
    desc: str | None = None
    cwe: str | None = None

    if clean_id:
        if report_state is None:
            return {
                "success": False,
                "error": f"Report state unavailable; cannot find '{clean_id}'",
            }
        matched = next(
            (
                v
                for v in report_state.get_existing_vulnerabilities()
                if str(v.get("id")) == clean_id
            ),
            None,
        )
        if not matched:
            return {"success": False, "error": f"Finding with id '{clean_id}' not found"}
        clean_title = clean_title or matched.get("title")
        clean_endpoint = clean_endpoint or matched.get("endpoint") or matched.get("target")
        desc = matched.get("description")
        cwe = matched.get("cwe")

    if not clean_type and not clean_title and not clean_id:
        return {
            "success": False,
            "error": "Provide at least a 'finding_id', 'vuln_type', or 'title' to analyze.",
        }

    available_urls = _extract_sitemap_urls(report_state)
    if clean_endpoint and clean_endpoint not in available_urls:
        available_urls.append(clean_endpoint)

    candidates = find_chain_candidates(
        vuln_type=clean_type,
        title=clean_title,
        description=desc,
        cwe=cwe,
        sitemap_urls=available_urls,
    )

    if not candidates:
        return {
            "success": True,
            "count": 0,
            "message": (
                "No automatic exploit chain template matched this primitive. "
                "Review target workflows to determine if this unlocks another boundary."
            ),
            "candidates": [],
        }

    return {
        "success": True,
        "count": len(candidates),
        "message": (
            f"Found {len(candidates)} exploit chaining candidate(s). "
            "Test B targets to escalate severity."
        ),
        "candidates": [c.to_dict() for c in candidates],
        "chaining_rules": [
            "1. Confirm Bug A is real first with a concrete HTTP request/response.",
            "2. Test Target B within a 15-20 minute budget. If not confirmed, report A standalone.",
            "3. When Target B is confirmed, link them using link_exploit_chain.",
        ],
    }


def _validate_link_inputs(
    primary: str,
    secondaries: list[str],
    title: str,
    severity: str,
    impact: str,
    poc: str,
) -> str | None:
    if not primary or not secondaries or not title:
        return "primary_finding_id, secondary_finding_ids, and chain_title cannot be empty"
    if severity not in _VALID_SEVERITIES or severity in ("info", "low"):
        return f"escalated_severity must be 'medium', 'high' or 'critical', got '{severity}'"
    if not impact or not poc:
        return "escalated_impact and combined_poc cannot be empty"
    return None


def _link_impl(
    *,
    primary_finding_id: str,
    secondary_finding_ids: list[str],
    chain_title: str,
    escalated_severity: str,
    escalated_impact: str,
    combined_poc: str,
    target_c: str | None = None,
) -> dict[str, Any]:
    clean_primary = (primary_finding_id or "").strip()
    clean_title = (chain_title or "").strip()
    clean_severity = (escalated_severity or "").strip().lower()
    clean_impact = (escalated_impact or "").strip()
    clean_poc = (combined_poc or "").strip()

    validation_err = _validate_link_inputs(
        clean_primary,
        secondary_finding_ids,
        clean_title,
        clean_severity,
        clean_impact,
        clean_poc,
    )
    if validation_err:
        return {"success": False, "error": validation_err}

    report_state = get_global_report_state()
    if report_state is None:
        return {"success": False, "error": "Report state unavailable - no reports on file"}

    vuln_map = {str(v.get("id")): v for v in report_state.get_existing_vulnerabilities()}
    if clean_primary not in vuln_map:
        return {"success": False, "error": f"Primary finding '{clean_primary}' not found"}

    missing = [sec for sec in secondary_finding_ids if str(sec).strip() not in vuln_map]
    if missing:
        return {"success": False, "error": f"Secondary findings not found: {missing}"}

    chain_id = f"CHAIN-{clean_primary}"
    chain_metadata = {
        "chain_id": chain_id,
        "chain_title": clean_title,
        "is_chain_root": True,
        "primary_finding_id": clean_primary,
        "secondary_finding_ids": secondary_finding_ids,
        "target_c": clean_optional(target_c),
        "escalated_severity": clean_severity,
        "escalated_impact": clean_impact,
    }

    primary_update = {
        "title": f"[CHAIN] {clean_title}",
        "severity": clean_severity,
        "impact": (
            f"{clean_impact}\n\n[Chained Components: {clean_primary} -> "
            f"{', '.join(secondary_finding_ids)}]"
        ),
        "poc_script_code": f"### Multi-Hop Exploit Chain: {clean_title}\n\n{clean_poc}",
        "chain_metadata": chain_metadata,
    }

    try:
        report_state.update_vulnerability_report(
            clean_primary,
            primary_update,
            update_reason=f"Escalated into exploit chain: {clean_title}",
        )
    except Exception as exc:
        logger.exception("Failed to update primary finding with chain metadata")
        return {"success": False, "error": f"Failed to update primary finding: {exc!s}"}

    for sec_id in secondary_finding_ids:
        sec_clean = str(sec_id).strip()
        sec_update = {
            "chain_metadata": {
                "chain_id": chain_id,
                "chain_title": clean_title,
                "is_chain_root": False,
                "chained_into": clean_primary,
            }
        }
        try:
            report_state.update_vulnerability_report(
                sec_clean,
                sec_update,
                update_reason=f"Linked as component of exploit chain: {clean_title}",
            )
        except Exception:  # noqa: BLE001
            logger.warning("Could not link secondary finding %s to chain %s", sec_clean, chain_id)

    logger.info("Exploit chain %s created successfully (%s)", chain_id, clean_title)
    return {
        "success": True,
        "chain_id": chain_id,
        "primary_finding_id": clean_primary,
        "secondary_finding_ids": secondary_finding_ids,
        "chain_title": clean_title,
        "escalated_severity": clean_severity,
        "message": (
            f"Exploit chain '{chain_id}' established successfully. Primary finding "
            f"'{clean_primary}' upgraded to {clean_severity.upper()} with multi-hop PoC."
        ),
    }


@function_tool(timeout=15)
async def suggest_exploit_chains(
    ctx: RunContextWrapper,
    finding_id: str | None = None,
    vuln_type: str | None = None,
    title: str | None = None,
    endpoint: str | None = None,
) -> str:
    """Analyze a vulnerability primitive and suggest A -> B -> C exploit chain candidates.

    Use this when you discover an initial vulnerability (especially Low or Medium,
    such as Open Redirect, CORS misconfiguration, SSRF, IDOR, or Secret Leak).
    Returns concrete hypothesis candidates, target endpoints to search for, and
    verification steps to escalate impact to High or Critical.

    Args:
        ctx: Run context wrapper.
        finding_id: Optional ID of an already-filed vulnerability report (e.g. 'VULN-001').
        vuln_type: Optional vulnerability class (e.g. 'open_redirect', 'ssrf', 'cors', 'idor').
        title: Optional title or summary of the vulnerability.
        endpoint: Optional endpoint URL where the vulnerability was found.
    """
    res = _suggest_impl(
        finding_id=finding_id,
        vuln_type=vuln_type,
        title=title,
        endpoint=endpoint,
    )
    return json.dumps(res, indent=2)


@function_tool(timeout=15)
async def link_exploit_chain(
    ctx: RunContextWrapper,
    primary_finding_id: str,
    secondary_finding_ids: list[str],
    chain_title: str,
    escalated_severity: str,
    escalated_impact: str,
    combined_poc: str,
    target_c: str | None = None,
) -> str:
    """Link multiple confirmed findings into a single escalated exploit chain.

    Combines an entry primitive (Bug A) with secondary vulnerabilities (Bug B, Bug C)
    into a unified attack chain, upgrading severity to High or Critical with a
    comprehensive multi-hop proof of concept.

    Args:
        ctx: Run context wrapper.
        primary_finding_id: The ID of the entry finding (e.g. 'VULN-001').
        secondary_finding_ids: List of secondary finding IDs (e.g. ['VULN-002']).
        chain_title: Descriptive title (e.g. 'Account Takeover via Open Redirect & OAuth').
        escalated_severity: The upgraded severity for the chain ('high' or 'critical').
        escalated_impact: Detailed explanation of the combined business impact.
        combined_poc: Complete step-by-step reproduction instructions or exploit script.
        target_c: Optional third-hop target or final objective achieved.
    """
    res = _link_impl(
        primary_finding_id=primary_finding_id,
        secondary_finding_ids=secondary_finding_ids,
        chain_title=chain_title,
        escalated_severity=escalated_severity,
        escalated_impact=escalated_impact,
        combined_poc=combined_poc,
        target_c=target_c,
    )
    return json.dumps(res, indent=2)
