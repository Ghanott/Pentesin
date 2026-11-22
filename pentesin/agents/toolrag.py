"""Lexical Okapi BM25 tool projection (ToolRAG) adapted from ARTEX agent/toolrag.go."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Sequence

    from agents import Tool


DEFAULT_TOOL_RAG_TOP_K = 12
MIN_CATALOG_SIZE = 20

# Core tools that are always preserved when ToolRAG is enabled so lifecycle,
# reporting, evidence, coverage, coordination, and recon triage never break.
CORE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "think",
        "load_skill",
        "create_todo",
        "list_todos",
        "update_todo",
        "mark_todo_done",
        "mark_todo_pending",
        "create_note",
        "list_notes",
        "search_notes",
        "get_note",
        "update_note",
        "record_coverage",
        "update_coverage",
        "list_coverage",
        "get_threat_model",
        "save_threat_model",
        "amend_threat_model",
        "web_search",
        "web_get_contents",
        "triage_recon_data",
        "harvest_api_surface",
        "create_vulnerability_report",
        "create_dependency_report",
        "update_vulnerability_report",
        "list_reports",
        "get_report",
        "list_requests",
        "view_request",
        "repeat_request",
        "list_sitemap",
        "view_sitemap_entry",
        "scope_rules",
        "view_agent_graph",
        "send_message_to_agent",
        "wait_for_agents",
        "create_agent",
        "stop_agent",
        "wait_for_user",
        "agent_finish",
        "finish_scan",
        "finish_pr_review",
    }
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric tokenization matching ARTEX toolrag.go."""
    return _TOKEN_RE.findall((text or "").lower())


def _tool_document_text(tool: Any) -> str:
    name = str(getattr(tool, "name", "") or "")
    desc = str(getattr(tool, "description", "") or "")
    schema = getattr(tool, "params_json_schema", None)
    props_text = ""
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict):
            props_text = " ".join(str(k) for k in props)
    return f"{name} {desc} {props_text}"


def bm25_score(query: str, tools: Sequence[Any]) -> list[float]:
    """Okapi BM25 (k1=1.2, b=0.75) over each candidate tool's name, description, and schema."""
    k1 = 1.2
    b = 0.75
    n_docs = len(tools)
    if n_docs == 0:
        return []

    docs: list[Counter[str]] = []
    lengths: list[float] = []
    df: Counter[str] = Counter()
    total_len = 0.0

    for tool in tools:
        tf = Counter(tokenize(_tool_document_text(tool)))
        doc_len = float(sum(tf.values()))
        docs.append(tf)
        lengths.append(doc_len)
        total_len += doc_len
        for term in tf:
            df[term] += 1

    avg_len = max(total_len / max(n_docs, 1), 1.0)
    scores = [0.0] * n_docs
    seen_q: set[str] = set()

    for q_term in tokenize(query):
        if q_term in seen_q or df[q_term] == 0:
            continue
        seen_q.add(q_term)
        idf = math.log(1.0 + (n_docs - df[q_term] + 0.5) / (df[q_term] + 0.5))
        for idx, tf in enumerate(docs):
            freq = float(tf.get(q_term, 0))
            if freq > 0:
                denom = freq + k1 * (1.0 - b + b * (lengths[idx] / avg_len))
                scores[idx] += idf * freq * (k1 + 1.0) / denom

    return scores


def project_tools(
    query: str,
    tools: Sequence[Tool],
    *,
    keep_names: frozenset[str] | set[str] = CORE_TOOL_NAMES,
    top_k: int = DEFAULT_TOOL_RAG_TOP_K,
) -> tuple[list[Tool], bool]:
    """Keep core tools plus the top-k highest-scoring non-core tools, preserving order.

    Returns ``(projected_tools, was_projected)``. Falls back to the full list
    when ``query`` is empty or ``len(tools) < MIN_CATALOG_SIZE``.
    """
    if not query.strip() or len(tools) < MIN_CATALOG_SIZE:
        return list(tools), False

    candidates = [t for t in tools if getattr(t, "name", "") not in keep_names]
    if not candidates:
        return list(tools), False

    scores = bm25_score(query, candidates)
    ranked_indices = sorted(
        range(len(candidates)),
        key=lambda i: (-scores[i], str(getattr(candidates[i], "name", ""))),
    )
    selected = {
        str(getattr(candidates[i], "name", "")) for i in ranked_indices[: max(1, top_k)]
    }
    projected = [
        t
        for t in tools
        if getattr(t, "name", "") in keep_names or getattr(t, "name", "") in selected
    ]
    return projected, True


def format_tool_rag_debug(query: str, tools: Sequence[Tool], selected: Sequence[Tool]) -> str:
    return json.dumps(
        {
            "query": query,
            "total": len(tools),
            "selected": len(selected),
            "tools": [getattr(t, "name", "") for t in selected],
        }
    )
