"""The runner attaches MCP connections source-agnostically.

When a caller supplies ``mcp_connection_requests`` the runner attaches those;
when it does not, the runner reads ``~/.pentesin/mcp-servers.json`` itself and wraps
each config in a bare request. Either way the one shared ``attach_mcp_requests``
routine does the connecting.
"""

from __future__ import annotations

import importlib
import types
from typing import Any

import pytest
from agents import ModelSettings

import pentesin.tools.mcp as mcp_pkg
import pentesin.tools.notes.tools as notes_tools
import pentesin.tools.todo.tools as todo_tools
from pentesin.agents import factory
from pentesin.core import runner
from pentesin.core.agents import AgentCoordinator
from pentesin.runtime import session_manager
from pentesin.tools.mcp import McpConnectionConfig, McpConnectionRequest, context_mode
from pentesin.tools.mcp import client as mcp_client
from pentesin.tools.mcp.context_mode import context_mode_request


_test_mcp_client = importlib.import_module("tests.test_mcp_client")
FakeMCPServer: Any = _test_mcp_client.FakeMCPServer
_mcp_tool: Any = _test_mcp_client._mcp_tool


def _built_server(server: Any) -> Any:
    return mcp_client.BuiltMcpServer(server, None)


@pytest.mark.asyncio
async def test_context_mode_launches_only_inside_the_scan_container() -> None:
    environment = types.SimpleNamespace(
        value={"http_proxy": "http://127.0.0.1:48080", "OPENAI_API_KEY": "must-not-leak"}
    )
    session = types.SimpleNamespace(
        state=types.SimpleNamespace(
            container_id="abc123", manifest=types.SimpleNamespace(environment=environment)
        )
    )
    request = await context_mode_request(session, "web-17")
    config = request.config
    assert config.command == "docker"
    assert config.args[:7] == [
        "exec",
        "-i",
        "--user",
        "pentester",
        "--workdir",
        "/workspace",
        "abc123",
    ]
    assert config.args[7:9] == ["/usr/bin/env", "-i"]
    assert "CONTEXT_MODE_DIR=/tmp/pentesin-context-mode/web-17" in config.args
    assert "CONTEXT_MODE_PROJECT_DIR=/workspace" in config.args
    assert config.env == {}
    assert "http_proxy=http://127.0.0.1:48080" in config.args
    assert "must-not-leak" not in " ".join(config.args)
    assert "ctx_execute" in (config.allowed_tools or [])
    assert "ctx_purge" not in (config.allowed_tools or [])
    other = await context_mode_request(session, "web-18")
    assert other.config.args != config.args


@pytest.mark.asyncio
async def test_context_mode_resolves_deferred_container(monkeypatch: pytest.MonkeyPatch) -> None:
    resolved = types.SimpleNamespace(state=types.SimpleNamespace(container_id="abc123"))

    class Deferred:
        async def resolve(self) -> Any:
            return resolved

    monkeypatch.setattr(context_mode, "DeferredSandboxSession", Deferred)
    request = await context_mode_request(Deferred(), "web-17")
    assert "abc123" in request.config.args


@pytest.mark.asyncio
@pytest.mark.parametrize("scan_id", ["", "../scan", "a/b", "scan;id", "é"])
async def test_context_mode_rejects_invalid_storage_ids(scan_id: str) -> None:
    with pytest.raises(ValueError, match="invalid scan id"):
        await context_mode_request(object(), scan_id)


@pytest.mark.asyncio
async def test_context_mode_rejects_non_docker_sandbox() -> None:
    with pytest.raises(ValueError, match="Docker sandbox"):
        await context_mode_request(types.SimpleNamespace(state=object()), "web-17")


def test_stdio_server_honors_configured_session_timeout() -> None:
    config = McpConnectionConfig(
        name="context_mode", transport="stdio", command="docker", session_timeout_seconds=120
    )
    built = mcp_client._build_server(config)
    assert built.server.client_session_timeout_seconds == 120


def _settings() -> Any:
    return types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
            timeout=300,
            prompt_cache=True,
            extra_headers=None,
            extra_body=None,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
    )


def _wire_runner(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)
    monkeypatch.setattr(runner, "load_settings", _settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _s: None)
    monkeypatch.setattr(runner, "uses_chat_completions_tool_schema", lambda _m, _s: False)
    monkeypatch.setattr(todo_tools, "hydrate_todos_from_disk", lambda _d: None)
    monkeypatch.setattr(notes_tools, "hydrate_notes_from_disk", lambda _d: None)

    async def _create_or_reuse(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"client": object(), "session": object(), "caido_client": None}

    async def _cleanup(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)
    monkeypatch.setattr(runner, "build_root_task", lambda _c: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _c: {})
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_k: ModelSettings())
    monkeypatch.setattr(runner, "build_pentesin_agent", lambda **_k: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_k: lambda **_kk: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())
    monkeypatch.setattr(
        mcp_client,
        "_build_server",
        lambda config: _built_server(FakeMCPServer(config.name, [])),
    )

    async def _run_agent_loop(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(runner, "run_agent_loop", _run_agent_loop)


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_runner_context_mode_is_opt_in_and_preserves_supplied_requests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, enabled: bool
) -> None:
    _wire_runner(monkeypatch, tmp_path)

    async def create_session(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        session = types.SimpleNamespace(state=types.SimpleNamespace(container_id="abc123"))
        return {"client": object(), "session": session, "caido_client": None}

    monkeypatch.setattr(session_manager, "create_or_reuse", create_session)
    captured: list[McpConnectionRequest] = []
    original_register = mcp_pkg.McpRegistry.register

    def capture(registry: Any, request: McpConnectionRequest) -> Any:
        captured.append(request)
        return original_register(registry, request)

    monkeypatch.setattr(mcp_pkg.McpRegistry, "register", capture)
    supplied = [
        McpConnectionRequest(config=McpConnectionConfig(name="db", url="https://example.com"))
    ]
    await runner.run_pentesin_scan(
        scan_config={"targets": [], "context_mode": enabled},
        scan_id="web-17",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_connection_requests=supplied,
    )
    assert [request.config.name for request in captured] == (
        ["db", "context_mode"] if enabled else ["db"]
    )
    assert len(supplied) == 1


@pytest.mark.asyncio
async def test_runner_context_mode_failure_does_not_abort_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    phases: list[str] = []
    await runner.run_pentesin_scan(
        scan_config={"targets": [], "context_mode": True},
        scan_id="web-17",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_connection_requests=[],
        status_sink=phases.append,
    )
    assert "Context Mode unavailable; continuing without it" in phases


@pytest.mark.asyncio
async def test_none_default_attaches_from_the_user_config_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)

    file_config = McpConnectionConfig(
        name="local_fs", transport="stdio", command="npx", notes="local files"
    )
    monkeypatch.setattr(mcp_pkg, "load_user_mcp_configs", lambda: [file_config])

    captured: list[McpConnectionRequest] = []
    original_register = mcp_pkg.McpRegistry.register

    def _capture(registry: Any, request: McpConnectionRequest) -> Any:
        captured.append(request)
        return original_register(registry, request)

    monkeypatch.setattr(mcp_pkg.McpRegistry, "register", _capture)

    await runner.run_pentesin_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-none",
        image="img",
        coordinator=AgentCoordinator(),
    )

    # Each config from the file is wrapped in a bare request: no provider, no
    # transform, no explicit purpose (purpose falls back to notes at attach time).
    (request,) = captured
    assert request.config is file_config
    assert request.provider is None
    assert request.result_transform is None
    assert request.purpose is None


@pytest.mark.asyncio
async def test_supplied_requests_are_attached_and_the_user_file_is_not_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)

    def _fail_if_read() -> list[Any]:
        raise AssertionError("load_user_mcp_configs must not be read when requests are supplied")

    monkeypatch.setattr(mcp_pkg, "load_user_mcp_configs", _fail_if_read)

    captured: list[McpConnectionRequest] = []
    original_register = mcp_pkg.McpRegistry.register

    def _capture(registry: Any, request: McpConnectionRequest) -> Any:
        captured.append(request)
        return original_register(registry, request)

    monkeypatch.setattr(mcp_pkg.McpRegistry, "register", _capture)

    supplied = [
        McpConnectionRequest(
            config=McpConnectionConfig(name="db", url="https://mcp.example.com"),
            provider="supabase",
        )
    ]

    await runner.run_pentesin_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-supplied",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_connection_requests=supplied,
    )

    assert captured == supplied


@pytest.mark.asyncio
async def test_roster_is_persisted_even_without_a_status_sink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """The viewer reads the roster off disk, so persistence must not depend on the
    interface status sink: with ``mcp_status_sink=None`` the configured roster is
    still written, carrying only non-secret lifecycle fields."""
    _wire_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(
        mcp_pkg,
        "load_user_mcp_configs",
        lambda: [McpConnectionConfig(name="local_fs", transport="stdio", command="npx")],
    )
    monkeypatch.setattr(
        mcp_client,
        "_build_server",
        lambda _config: _built_server(FakeMCPServer("local_fs", [])),
    )

    persisted: list[list[dict[str, Any]]] = []

    def _capture_persist(roster: list[dict[str, Any]]) -> None:
        persisted.append(roster)

    monkeypatch.setattr(runner, "_persist_mcp_status", _capture_persist)

    await runner.run_pentesin_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-persist",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_status_sink=None,
    )

    assert persisted, "roster must persist even when no status sink is attached"
    assert persisted[0] == [
        {
            "name": "local_fs",
            "provider": None,
            "tool_count": 0,
            "dead": False,
            "state": "configured",
        }
    ]


@pytest.mark.asyncio
async def test_warmup_listing_failure_does_not_interrupt_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    _wire_runner(monkeypatch, tmp_path)

    server = FakeMCPServer("db", [])

    async def _failing_list_tools(
        run_context: Any = None,
        agent: Any = None,
    ) -> list[Any]:
        del run_context, agent
        raise RuntimeError("catalog unavailable")

    server.list_tools = _failing_list_tools

    monkeypatch.setattr(
        mcp_client,
        "_build_server",
        lambda _config: _built_server(server),
    )
    root_builds: list[dict[str, Any]] = []
    monkeypatch.setattr(runner, "build_pentesin_agent", lambda **kwargs: root_builds.append(kwargs))

    await runner.run_pentesin_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-mcp-list-failure",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_connection_requests=[
            McpConnectionRequest(
                config=McpConnectionConfig(name="db", url="https://mcp.example.com")
            )
        ],
    )

    assert len(root_builds) == 1


@pytest.mark.asyncio
async def test_warmed_tool_counts_reach_root_and_child_agent_builds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    server = FakeMCPServer("db", [_mcp_tool(f"tool_{index}") for index in range(3)])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(server))

    root_builds: list[dict[str, Any]] = []

    def _build_root(**kwargs: Any) -> object:
        root_builds.append(kwargs)
        return object()

    monkeypatch.setattr(
        runner,
        "build_pentesin_agent",
        _build_root,
    )
    child_builds: list[dict[str, Any]] = []

    def _build_child(**kwargs: Any) -> object:
        child_builds.append(kwargs)
        return object()

    monkeypatch.setattr(
        factory,
        "build_pentesin_agent",
        _build_child,
    )
    real_make_child_factory = factory.make_child_factory
    child_factory_capture: dict[str, Any] = {}

    def _make_child_factory(**kwargs: Any) -> Any:
        child_factory_capture["context"] = kwargs["system_prompt_context"]
        child_factory_capture["factory"] = real_make_child_factory(**kwargs)
        return child_factory_capture["factory"]

    monkeypatch.setattr(runner, "make_child_factory", _make_child_factory)
    request = McpConnectionRequest(
        config=McpConnectionConfig(name="db", url="https://mcp.example.com", notes="database")
    )

    await runner.run_pentesin_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-mcp-prompt-counts",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_connection_requests=[request],
    )

    root_context = root_builds[0]["system_prompt_context"]
    assert root_context["mcp_connections"][0]["tool_count"] == 3
    assert child_factory_capture["context"] is root_context
    assert child_factory_capture["context"]["mcp_connections"][0]["tool_count"] == 3

    child_factory_capture["factory"](name="child", skills=[])
    assert child_builds[0]["system_prompt_context"] is child_factory_capture["context"]
    assert child_builds[0]["system_prompt_context"]["mcp_connections"][0]["tool_count"] == 3
