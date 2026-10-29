from __future__ import annotations

import asyncio
import base64
import json
import os
import types
import urllib.error

import pytest

from pentesin.interface import web_runner
from pentesin.interface.tui.live_view import TuiLiveView


@pytest.fixture(autouse=True)
def isolate_completion_files(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(web_runner, "run_dir_for", lambda name: tmp_path / name)


@pytest.mark.parametrize('resume', [False, True])
def test_scan_forwards_context_mode_without_host_mcp(monkeypatch: pytest.MonkeyPatch, tmp_path, resume: bool) -> None:
    captured: dict[str, object] = {}

    class Report:
        def __init__(self, _scan_id: str) -> None:
            pass

        def set_scan_config(self, config: dict[str, object]) -> None:
            captured["scan_config"] = config

        def save_run_data(self) -> None:
            pass

        def hydrate_from_run_dir(self) -> None:
            captured['hydrated'] = True

        def cleanup(self, **_kwargs: object) -> None:
            pass

        def get_run_dir(self) -> str:
            return "."

    async def run_scan(**kwargs: object) -> None:
        captured.update(kwargs)

    async def supervise(scan: object, *_args: object, **_kwargs: object) -> dict[str, str]:
        await scan(lambda *_args: None)
        return {"status": "completed"}

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(), runtime=types.SimpleNamespace(image="sandbox")
    )
    monkeypatch.setattr(web_runner, "load_settings", lambda: settings)
    monkeypatch.setattr(web_runner, 'run_dir_for', lambda _scan_id: tmp_path)
    state_dir = tmp_path / '.state'
    state_dir.mkdir()
    (state_dir / 'agents.json').write_text('{}')
    (state_dir / 'agents.db').write_bytes(b'checkpoint')
    monkeypatch.setattr(web_runner, "ReportState", Report)
    monkeypatch.setattr(web_runner, "set_global_report_state", lambda _report: None)
    monkeypatch.setattr(web_runner, "run_pentesin_scan", run_scan)
    monkeypatch.setattr(web_runner, "_supervise_scan", supervise)
    def failed_upload(*_args):
        raise urllib.error.URLError("artifact server unavailable")

    monkeypatch.setattr(web_runner, "_upload_artifacts", failed_upload)
    asyncio.run(web_runner._execute_job("http://127.0.0.1:8000", "runner", {
        "id": 9, "lease_token": "lease", "kind": "scan", "target": "https://lab.example",
        "profile": {"model": "vendor/model"}, "context_mode": True, 'resume': resume,
    }))
    assert captured["scan_config"]["context_mode"] is True
    assert captured["scan_id"] == "web-9"
    assert captured["scan_config"]["targets"][0]["type"] == "web_application"
    assert captured["mcp_connection_requests"] == []
    assert captured.get('hydrated', False) is resume


def test_resume_rejects_missing_checkpoint(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(web_runner, 'load_settings', lambda: types.SimpleNamespace(llm=types.SimpleNamespace()))
    monkeypatch.setattr(web_runner, 'run_dir_for', lambda _scan_id: tmp_path)
    with pytest.raises(ValueError, match='checkpoint is missing'):
        asyncio.run(web_runner._execute_job('http://127.0.0.1:8000', 'runner', {
            'id': 9, 'lease_token': 'lease', 'kind': 'scan', 'target': 'https://lab.example',
            'profile': {'model': 'vendor/model'}, 'resume': True,
        }))


def test_base_url_allows_loopback_only() -> None:
    assert web_runner.validate_base_url("http://localhost:8000/") == "http://localhost:8000"
    for url in ("https://127.0.0.1", "http://example.com", "http://127.0.0.1/path", "http://user@localhost"):
        with pytest.raises(ValueError):
            web_runner.validate_base_url(url)


def test_redacts_sensitive_dict_values() -> None:
    assert web_runner._redact({"api_key": "secret", "data": [{"token": "abc", "name": "agent"}]}) == {
        "api_key": "[redacted]", "data": [{"token": "[redacted]", "name": "agent"}]
    }


def test_job_validation_rejects_unsupported_kind() -> None:
    with pytest.raises(ValueError):
        web_runner._safe_job({"id": "1", "lease_token": "x", "kind": "source_scan", "profile": {}})


def test_clean_environment_drops_model_credentials_but_restores_worker_control(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "inherited-secret")
    monkeypatch.setenv("PENTESIN_RUNNER_TOKEN", "old-token")
    env = web_runner._clean_env(control_url="http://127.0.0.1:8000", control_token="worker-token")
    assert "OPENAI_API_KEY" not in env
    assert env["PENTESIN_RUNNER_TOKEN"] == "worker-token"
    assert env["PENTESIN_APP_URL"] == "http://127.0.0.1:8000"


def test_model_test_requires_profile_model() -> None:
    async def run() -> None:
        with pytest.raises(ValueError, match="invalid model profile"):
            await web_runner._run_model_test({"profile": {}})
    asyncio.run(run())


def test_model_test_sends_chat_without_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeModel:
        async def get_response(self, **kwargs: object) -> object:
            assert kwargs["tools"] == []
            assert kwargs["model_settings"].tool_choice is None
            assert kwargs["input"] == "test"
            return types.SimpleNamespace(output=[types.SimpleNamespace(raw_item=types.SimpleNamespace(content=[types.SimpleNamespace(type="output_text", text="test berhasil")]))])

    class FakeProvider:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def get_model(self, _model: str) -> FakeModel:
            return FakeModel()

    monkeypatch.setattr("pentesin.config.models.PentesinProvider", FakeProvider)
    async def run() -> dict[str, object]:
        return await web_runner._run_model_test({"profile": {"model": "vendor/model"}})
    result = asyncio.run(run())
    assert result["ok"] is True
    assert result["connection"] is True
    assert "tool_call_supported" not in result
    assert isinstance(result["latency_ms"], int)
    assert result["error"] is None


def test_once_returns_failure_for_control_plane_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise urllib.error.URLError("offline")
    monkeypatch.setattr(web_runner, "_post_json", fail)
    assert asyncio.run(web_runner.run_worker("http://127.0.0.1:8000", "token", once=True)) == 1


def test_artifact_upload_allowlists_and_bounds_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    assert web_runner.MAX_ARTIFACT_BYTES == 1_000_000
    assert 'run.json' not in web_runner.ARTIFACT_NAMES
    files = {
        "penetration_test_report.md": b"report",
        "run.json": b'{"status":"done"}',
        "oversize": b"x",
    }
    class FakeFile:
        def __init__(self, name: str) -> None:
            self.name = name
        def stat(self) -> types.SimpleNamespace:
            size = web_runner.MAX_ARTIFACT_BYTES + 1 if self.name == "findings.sarif" else len(files.get(self.name, b""))
            return types.SimpleNamespace(st_size=size)
        def is_file(self) -> bool:
            return self.name in files or self.name == "findings.sarif"
        def read_bytes(self) -> bytes:
            return files.get(self.name, b"x" * (web_runner.MAX_ARTIFACT_BYTES + 1))
    class FakeRoot:
        def resolve(self) -> "FakeRoot":
            return self
        def __truediv__(self, name: str) -> FakeFile:
            return FakeFile(name)
    monkeypatch.setattr(web_runner, "Path", lambda _value: FakeRoot())
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(web_runner, "_post_json", lambda url, _token, body, **kwargs: calls.append((url, body)) or {})
    web_runner._upload_artifacts("http://127.0.0.1:8000", "runner", {"id": 9, "lease_token": "lease"}, "fake-run-dir")
    assert [url.rsplit("/", 1)[-1] for url, _body in calls] == ["penetration_test_report.md"]
    assert base64.b64decode(calls[0][1]["content_base64"]) == b"report"
    assert all(body["lease_token"] == "lease" for _url, body in calls)


def test_model_test_worker_publishes_terminal_result_without_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    job = {"id": 17, "lease_token": "lease", "kind": "model_test", "profile": {}}
    result = {"ok": False, "connection": True, "latency_ms": 42, "error": "test request failed", "api_key": "must-not-leak"}
    calls: list[tuple[str, dict[str, object]]] = []

    class Process:
        returncode = 0

        async def communicate(self, _data: bytes) -> tuple[bytes, None]:
            return json.dumps(result).encode(), None

    async def create(*_args: object, **_kwargs: object) -> Process:
        return Process()

    def post(url: str, _token: str, body: dict[str, object] | None = None, **_kwargs: object) -> dict[str, object]:
        if url.endswith("/claim"):
            return {"job": job}
        calls.append((url, body or {}))
        return {}

    monkeypatch.setattr(web_runner.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(web_runner, "_post_json", post)
    assert asyncio.run(web_runner.run_worker("http://127.0.0.1:8000", "runner-secret", once=True)) == 0
    assert len(calls) == 1
    url, body = calls[0]
    assert url.endswith("/api/internal/runner/v1/scans/17/heartbeat")
    assert body["status"] == "failed"
    assert body["test_result"] == {"ok": False, "connection": True, "latency_ms": 42, "error": "test request failed", "api_key": "[redacted]"}
    assert "runner-secret" not in json.dumps(body)


def test_stop_command_cancels_parked_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    cancelled = []
    sent = []

    class Coordinator:
        async def graph_snapshot(self):
            return {'root': None}, {'root': 'failed'}, {'root': 'Root'}, {}

    async def scan(_event_sink):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    def post(_url, _token, body, **_kwargs):
        sent.append(body)
        return {'commands': [{'id': 1, 'type': 'stop'}]} if not body.get('status') else {'commands': []}

    monkeypatch.setattr(web_runner, '_post_json', post)
    outcome = asyncio.run(web_runner._supervise_scan(
        scan, Coordinator(), TuiLiveView(), types.SimpleNamespace(vulnerability_reports=[], cleanup=lambda **_kwargs: None),
        {'id': 9, 'lease_token': 'lease'}, base='http://127.0.0.1:8000', token='runner',
    ))
    assert cancelled == [True]
    assert outcome['status'] == 'stopped'
    assert sent[-1]['status'] == 'stopped'


@pytest.mark.parametrize('agent_failed', [False, True])
def test_heartbeat_forwards_live_events_agent_graph_and_findings(monkeypatch: pytest.MonkeyPatch, agent_failed: bool) -> None:
    sent: list[dict[str, object]] = []
    rate_limit = 'openai.RateLimitError: 429 FreeUsageLimitError: Free usage limit reached'
    acknowledgements: list[str] = []

    class Coordinator:
        async def graph_snapshot(self) -> tuple[dict[str, object], dict[str, str], dict[str, str], dict[str, object]]:
            return {"child": "root", "root": None}, {"root": "running", "child": "failed" if agent_failed else "waiting"}, {"root": "Root", "child": "Worker"}, {"child": rate_limit}

        async def send(self, *_args: object, **_kwargs: object) -> bool:
            return True

    class Report:
        vulnerability_reports: list[dict[str, object]] = [{"id": "f-1", "title": "finding", "severity": "high"}]

        def cleanup(self, **_kwargs: object) -> None:
            pass

        def get_run_dir(self) -> str:
            return "local-run"

    def post(url: str, _token: str, body: dict[str, object] | None = None, **_kwargs: object) -> dict[str, object]:
        if "/heartbeat" in url:
            sent.append(body or {})
            return {"commands": [] if (body or {}).get("status") else [{"id": "01a16c7f-094a-7271-9ca9-6d0efea65267", "agent_id": "child", "message": "Lanjutkan"}]}
        acknowledgements.append(url)
        return {}

    async def scan(capture_event: object) -> None:
        capture_event("child", types.SimpleNamespace(
            type="run_item_stream_event",
            item=types.SimpleNamespace(type="message_output_item", raw_item=types.SimpleNamespace(content=[types.SimpleNamespace(type="output_text", text="hello")]))
        ))
        assert live.events
        await asyncio.sleep(0.03)

    live = TuiLiveView()
    monkeypatch.setattr(web_runner, "HEARTBEAT_SECONDS", 0.005)
    monkeypatch.setattr(web_runner, "_post_json", post)
    result = asyncio.run(web_runner._supervise_scan(
        scan, Coordinator(), live, Report(), {"id": 7, "lease_token": "lease"},
        base="http://127.0.0.1:8000", token="runner",
    ))
    assert result["status"] == ('failed' if agent_failed else 'completed')
    assert sent
    assert {agent["id"]: agent["parent_id"] for agent in sent[0]["agents"]}["child"] == "root"
    assert sent[0]["events"][0]["source_id"]
    assert sent[0]["events"][0]["version"] == 0
    assert sent[0]["events"][0]["data"]["content"] == "hello"
    assert sent[-1]["status"] == ('failed' if agent_failed else 'completed')
    assert sent[-1]["findings"][0]["action"] == "upsert"
    errors = [event for body in sent for event in body["events"]
              if event["data"].get("metadata", {}).get("source") == "agent_error"]
    assert acknowledgements
    assert all(url.endswith('/commands/01a16c7f-094a-7271-9ca9-6d0efea65267/ack') for url in acknowledgements)
    assert len(errors) == 1
    assert errors[0]["agent_id"] == "child"
    assert rate_limit in errors[0]["data"]["content"]


def test_completion_survives_delivery_failure_and_retries_before_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    cleaned = []

    class Coordinator:
        async def graph_snapshot(self):
            return {"root": None}, {"root": "completed"}, {"root": "Root"}, {}

    async def scan(_capture):
        return None

    def offline(_url, _token, body, **_kwargs):
        if body.get("status"):
            assert cleaned == ["completed"]
        raise urllib.error.URLError("offline")

    job = {"id": 9, "lease_token": "lease"}
    monkeypatch.setattr(web_runner, "_post_json", offline)
    outcome = asyncio.run(web_runner._supervise_scan(
        scan, Coordinator(), TuiLiveView(),
        types.SimpleNamespace(vulnerability_reports=[], cleanup=lambda **kw: cleaned.append(kw["status"])),
        job, base="http://127.0.0.1:8000", token="runner",
    ))
    assert outcome == {"status": "completed"}
    pending = web_runner._completion_path(job)
    assert pending.is_file()

    def online(url, _token, body=None, **_kwargs):
        calls.append((url, body))
        return {"job": None} if url.endswith("/claim") else {}

    monkeypatch.setattr(web_runner, "_post_json", online)
    assert asyncio.run(web_runner.run_worker("http://127.0.0.1:8000", "runner", once=True)) == 0
    assert calls[0][1]["status"] == "completed"
    assert calls[1][0].endswith("/claim")
    assert not pending.exists()


@pytest.mark.parametrize("code,expected", [(409, True), (503, False)])
def test_completion_fencing_discards_stale_lease_but_retains_outage(monkeypatch: pytest.MonkeyPatch, code: int, expected: bool) -> None:
    job = {"id": 9, "lease_token": "old"}
    pending = web_runner._save_completion("http://127.0.0.1:8000", job, {"status": "completed", "lease_token": "old"})

    def fail(url, *_args, **_kwargs):
        raise urllib.error.HTTPError(url, code, "rejected", {}, None)

    monkeypatch.setattr(web_runner, "_post_json", fail)
    assert asyncio.run(web_runner._flush_completions("http://127.0.0.1:8000", "runner")) is expected
    assert pending.exists() is not expected


def test_completion_retains_artifacts_for_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    job = {"id": 9}
    pending = web_runner._save_completion("http://127.0.0.1:8000", job, {"status": "completed", "lease_token": "lease"})
    monkeypatch.setattr(web_runner, "_post_json", lambda *_args: {})

    def fail_upload(*_args):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(web_runner, "_upload_artifacts", fail_upload)
    assert not asyncio.run(web_runner._flush_completions("http://127.0.0.1:8000", "runner"))
    assert pending.exists()
    monkeypatch.setattr(web_runner, "_upload_artifacts", lambda *_args: None)
    assert asyncio.run(web_runner._flush_completions("http://127.0.0.1:8000", "runner"))
    assert not pending.exists()


def test_unacknowledged_completion_prevents_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    web_runner._save_completion("http://127.0.0.1:8000", {"id": 9}, {"status": "completed", "lease_token": "lease"})
    urls = []

    def fail(url, *_args, **_kwargs):
        urls.append(url)
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(web_runner, "_post_json", fail)
    assert asyncio.run(web_runner.run_worker("http://127.0.0.1:8000", "runner", once=True)) == 1
    assert len(urls) == 1
    assert urls[0].endswith("/heartbeat")
