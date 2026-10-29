"""finish_scan confronts the root agent with the coverage the runtime can see."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from pentesin.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk
from pentesin.tools.finish.tool import _coverage_summary, _do_finish


if TYPE_CHECKING:
    from pathlib import Path


_GRAPH = {
    "statuses": {"agent-1": "completed"},
    "names": {"agent-1": "injection-tester"},
    "metadata": {"agent-1": {"skills": ["sql_injection", "xss"]}},
}


@pytest.fixture(autouse=True)
def _empty_ledger(tmp_path: Path) -> None:
    hydrate_coverage_from_disk(tmp_path)


def _record(risk_area: str) -> None:
    _record_impl(
        surface="POST /api/orders/{id}",
        risk_area=risk_area,
        outcome="no_issue_found",
        evidence="Parameters fuzzed; no anomalies.",
        agent_id="agent-1",
        agent_name="injection-tester",
    )


def test_unrecorded_risk_class_is_reported_back_to_the_root_agent() -> None:
    _record("SQL injection")

    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 1
    assert len(summary["coverage_gaps"]) == 1
    assert "xss" in summary["coverage_gaps"][0]
    assert "unexamined" in summary["coverage_gap_warning"]


def test_fully_accounted_coverage_raises_no_gap_warning() -> None:
    _record("SQL injection")
    _record("cross-site scripting")

    summary = _coverage_summary(_GRAPH)

    assert "coverage_gaps" not in summary
    assert "coverage_gap_warning" not in summary


@pytest.mark.parametrize(
    "outcome,complete",
    [("needs_follow_up", False), ("no_issue_found", True), (None, False)],
)
def test_finish_distinguishes_incomplete_assessment(
    monkeypatch: pytest.MonkeyPatch, outcome: str | None, complete: bool
) -> None:
    from pentesin.report import state  # noqa: PLC0415

    class Report:
        vulnerability_reports: tuple[()] = ()

        def update_scan_final_fields(self, **_kwargs: Any) -> None:
            pass

    monkeypatch.setattr(state, "get_global_report_state", Report)
    if outcome is not None:
        _record_impl(
            surface="GET /", risk_area="reachability", outcome=outcome,
            evidence="Recorded evidence", agent_id="root", agent_name="Root",
        )
    result = _do_finish(
        parent_id=None, executive_summary="Summary", methodology="Method",
        technical_analysis="Analysis", recommendations="Follow up", agent_graph={},
    )
    assert result["success"] is True
    assert result["assessment_complete"] is complete
    assert ("incomplete coverage" in result["message"]) is (not complete)


def test_an_empty_ledger_still_warns_first() -> None:
    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 0
    assert "No coverage was recorded" in summary["coverage_warning"]
