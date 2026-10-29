"""Every parameter of every scan-agent tool carries a description in its JSON schema.

The model only sees a parameter's docstring text through the schema. An ``Args:``
section that the docstring parser fails to recognise (for example because an
earlier line opens a markdown code fence it never closes) silently drops every
parameter description, so optional-but-conditionally-required fields such as
``confidence_rationale`` become anonymous nullable strings the model never fills.
"""

from __future__ import annotations

import pytest
from agents.tool import FunctionTool

from pentesin.agents import factory
from pentesin.agents.prompt import render_system_prompt
from pentesin.tools.agents_graph.tools import agent_finish
from pentesin.tools.finish.tool import finish_scan
from pentesin.tools.reporting.tool import create_vulnerability_report
from pentesin.tools.wait_for_user.tool import wait_for_user


_SCAN_AGENT_TOOLS = [
    tool
    for tool in (*factory._BASE_TOOLS, finish_scan, agent_finish, wait_for_user)
    if isinstance(tool, FunctionTool)
]


@pytest.mark.parametrize("tool", _SCAN_AGENT_TOOLS, ids=lambda tool: tool.name)
def test_every_parameter_has_a_description(tool: FunctionTool) -> None:
    properties = tool.params_json_schema.get("properties", {})
    missing = sorted(
        name
        for name, schema in properties.items()
        if not (isinstance(schema.get("description"), str) and schema["description"].strip())
    )
    assert not missing, f"{tool.name}: parameters without a description: {missing}"


def test_create_vulnerability_report_explains_confidence_rationale() -> None:
    schema = create_vulnerability_report.params_json_schema["properties"]
    assert "confidence" in create_vulnerability_report.params_json_schema["required"]
    rationale = schema["confidence_rationale"]["description"]
    assert "Required when" in rationale
    assert "high" in rationale


@pytest.mark.parametrize(
    "tool",
    [
        tool
        for tool in _SCAN_AGENT_TOOLS
        if tool.name in {"create_vulnerability_report", "create_dependency_report"}
    ],
    ids=lambda tool: tool.name,
)
def test_report_tools_require_indonesian_prose(tool: FunctionTool) -> None:
    assert "Bahasa Indonesia" in tool.description
    assert "CVE/CWE" in tool.description
    assert "schema enum values" in tool.description
    assert "code/payloads" in tool.description


@pytest.mark.parametrize("is_root", [True, False])
def test_report_language_in_system_prompt(is_root: bool) -> None:
    prompt = render_system_prompt(is_root=is_root, skills=[])
    assert "REPORT LANGUAGE:" in prompt
    assert "Bahasa Indonesia" in prompt
    assert "Never translate PoC code" in prompt
    assert "Apply this to new reports and report updates" in prompt
