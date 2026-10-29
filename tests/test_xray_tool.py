"""Tests for the xray scanner tool: scope refusal, argv shape, output parsing."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from pentesin.agents import factory
from pentesin.core.inputs import build_scan_targets
from pentesin.tools.xray import tools as xray


class _Result:
    def __init__(self, stdout: str = "", stderr: str = "", exit_code: int = 0) -> None:
        self.stdout = stdout.encode()
        self.stderr = stderr.encode()
        self.exit_code = exit_code


class _FakeSession:
    """Records every argv it is asked to run and replays canned results."""

    def __init__(self, report: str = "", exec_result: _Result | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._report = report
        self._exec_result = exec_result or _Result()

    async def mkdir(self, _path: str, *, parents: bool = False, **_kwargs: Any) -> None:  # noqa: ARG002
        return None

    async def write(self, _path: str, _data: Any, **_kwargs: Any) -> None:
        return None

    async def rm(self, _path: str, **_kwargs: Any) -> None:
        return None

    async def exec(self, *argv: str, **_kwargs: Any) -> _Result:
        self.calls.append(tuple(str(a) for a in argv))
        return self._exec_result

    async def read(self, _path: str) -> Any:
        return io.BytesIO(self._report.encode())


class _Ctx:
    def __init__(self, session: Any = None, scan_targets: list[str] | None = None) -> None:
        self.context = {
            "sandbox_session": session,
            "scan_targets": scan_targets if scan_targets is not None else [IN_SCOPE],
        }


IN_SCOPE = "https://app.example.com"


def test_build_argv_rejects_crawling() -> None:
    with pytest.raises(ValueError, match="crawling is disabled"):
        xray.build_argv(url=IN_SCOPE, mode="crawler", plugins=["xss"], json_output="/out.json")


def test_build_argv_url_mode_and_plugins() -> None:
    argv = xray.build_argv(
        url=IN_SCOPE, mode="url", plugins=["sqldet", "xss"], json_output="/out.json"
    )
    assert "--url" in argv
    assert "--basic-crawler" not in argv
    assert argv[argv.index("--plugins") + 1] == "sqldet,xss"


def test_scope_config_fences_host_port_disables_redirects_and_limits_crawl() -> None:
    config = xray._scope_config("https://app.example.com:8443")
    assert 'hostname_allowed: ["app.example.com"]' in config
    assert "port_allowed: [8443]" in config
    assert "max_redirect: 0" in config
    assert "max_qps: 10" in config
    assert "max_depth: 3" in config


def test_xray_scan_argv_loads_config_before_subcommand() -> None:
    report_path = f"{xray._RESULTS_DIR}/report.json"
    config_path = f"{xray._RESULTS_DIR}/config.yaml"
    argv = xray._xray_scan_argv(IN_SCOPE, "url", ["xss"], report_path, config_path)
    assert argv[:4] == ["xray", "--config", config_path, "webscan"]
    assert "--basic-crawler" not in argv
    assert "--url" in argv


def test_validate_target_accepts_an_authorized_host() -> None:
    url, error = xray._validate_target(IN_SCOPE, [IN_SCOPE])
    assert error is None
    assert url == IN_SCOPE


@pytest.mark.parametrize(
    "target",
    [
        "https://attacker.test",
        "https://other.example.com",
        "https://app.example.com.evil.test",
    ],
)
def test_validate_target_refuses_out_of_scope_hosts(target: str) -> None:
    url, error = xray._validate_target(target, [IN_SCOPE])
    assert url is None
    assert "out of scope" in (error or "")


def test_validate_target_refuses_an_unauthorized_port_on_an_authorized_host() -> None:
    url, error = xray._validate_target("https://app.example.com:8443", [IN_SCOPE])
    assert url is None
    assert "port" in (error or "")


def test_validate_target_allows_the_explicit_authorized_port() -> None:
    target = "https://app.example.com:8443"
    url, error = xray._validate_target(target, [target])
    assert error is None
    assert url == target


def test_validate_target_refuses_a_bare_host() -> None:
    _, error = xray._validate_target("app.example.com", [IN_SCOPE])
    assert "absolute http(s) URL" in (error or "")


def test_validate_target_refuses_credentials_but_preserves_query() -> None:
    _, error = xray._validate_target("https://u:p@app.example.com", [IN_SCOPE])
    assert "credentials" in (error or "")
    target = IN_SCOPE + "/search?q=a%26b&id=1&id=2"
    url, error = xray._validate_target(target, [IN_SCOPE])
    assert error is None
    assert url == target
    _, error = xray._validate_target(target + "#fragment", [IN_SCOPE])
    assert "fragment" in (error or "")


def test_validate_target_refuses_when_the_run_has_no_scope() -> None:
    _, error = xray._validate_target(IN_SCOPE, [])
    assert "no authorized live target" in (error or "")


def test_validate_plugins_rejects_unknown_names() -> None:
    plugins, error = xray._validate_plugins(["sqldet", "not-a-plugin"])
    assert plugins is None
    assert "not-a-plugin" in (error or "")


@pytest.mark.parametrize('plugins', [None, [], [' ', '']])
def test_explicit_plugins_required(plugins) -> None:
    assert xray._validate_plugins(plugins)[1] is not None


async def test_scan_rejects_crawler_and_missing_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('PENTESIN_XRAY_TERMS_ACCEPTED', '1')
    session = _FakeSession()
    for kwargs in ({'mode': 'crawler', 'plugins': ['xss']}, {}):
        result = json.loads(await xray._xray_scan_impl(_Ctx(session), IN_SCOPE, **kwargs))
        assert result['success'] is False
    assert session.calls == []


def test_validate_timeout_bounds() -> None:
    assert xray._validate_timeout(None)[0] == xray._DEFAULT_TIMEOUT_S
    assert xray._validate_timeout(0)[1] is not None
    assert xray._validate_timeout(xray._MAX_TIMEOUT_S + 1)[1] is not None


def test_parse_findings_handles_xray_json_array_and_blank_output() -> None:
    raw = json.dumps(
        [
            {
                "plugin": "sqldet",
                "target": {"url": "https://a/x"},
                "detail": {
                    "addr": "https://a/x?id=1",
                    "title": "SQL injection",
                    "payload": "test",
                    "snapshot": [["GET /", "HTTP/1.1 200 OK"]],
                },
                "create_time": 123456789,
            },
            {
                "plugin": "xss/reflected/default",
                "target": {"url": "https://a/y"},
                "detail": {"addr": "https://a/y", "title": "Reflected XSS"},
            },
        ]
    )
    findings, warning = xray._parse_findings(raw)
    assert warning is None
    assert [f["plugin"] for f in findings] == ["sqldet", "xss/reflected/default"]
    assert findings[0]["title"] == "SQL injection"
    assert findings[0]["url"] == "https://a/x?id=1"
    assert findings[0]["severity"] == "unknown"
    assert findings[0]["evidence"] == [["GET /", "HTTP/1.1 200 OK"]]

    empty, _ = xray._parse_findings("")
    assert empty == []


def test_parse_findings_warns_about_malformed_output() -> None:
    findings, warning = xray._parse_findings('[{"plugin":"xss"}, null]')
    assert len(findings) == 1
    assert warning is not None and "not valid JSON" in warning


def test_parse_findings_accepts_jsonl_compatibly() -> None:
    findings, warning = xray._parse_findings('{"plugin":"xss","detail":{"addr":"https://a/x"}}\n')
    assert warning is None
    assert findings[0]["url"] == "https://a/x"


async def test_xray_scan_refuses_out_of_scope_without_running_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTESIN_XRAY_TERMS_ACCEPTED", "1")
    session = _FakeSession()
    result = json.loads(await xray._xray_scan_impl(_Ctx(session), "https://attacker.test"))

    assert result["success"] is False
    assert "out of scope" in result["error"]
    assert session.calls == [], "a refused target must produce no subprocess at all"


async def test_xray_scan_refuses_unknown_plugin_without_running_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTESIN_XRAY_TERMS_ACCEPTED", "1")
    session = _FakeSession()
    result = json.loads(await xray._xray_scan_impl(_Ctx(session), IN_SCOPE, plugins=["nope"]))
    assert result["success"] is False
    assert session.calls == []


async def test_xray_scan_runs_in_scope_and_normalizes_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTESIN_XRAY_TERMS_ACCEPTED", "1")
    report = json.dumps(
        [
            {
                "plugin": "sqldet",
                "target": {"url": IN_SCOPE + "/x"},
                "detail": {"addr": IN_SCOPE + "/x?id=1", "title": "SQL injection"},
            }
        ]
    )
    session = _FakeSession(report=report)
    result = json.loads(await xray._xray_scan_impl(_Ctx(session), IN_SCOPE + '/x?id=1', plugins=['sqldet']))

    assert result["success"] is True
    assert result["count"] == 1
    assert result["by_severity"] == {"unknown": 1}
    assert result["findings"][0]["url"] == IN_SCOPE + "/x?id=1"
    assert result["severity_note"] is not None
    assert session.calls[0][:2] == ("xray", "--config")
    assert "--config" in session.calls[0]
    assert "--url" in session.calls[0]
    assert IN_SCOPE + '/x?id=1' in session.calls[0]
    assert '--basic-crawler' not in session.calls[0]


async def test_xray_scan_reports_timeout_as_a_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTESIN_XRAY_TERMS_ACCEPTED", "1")

    class _TimeoutSession(_FakeSession):
        async def exec(self, *argv: str, **_kwargs: Any) -> _Result:
            self.calls.append(tuple(str(a) for a in argv))
            raise TimeoutError

    result = json.loads(await xray._xray_scan_impl(_Ctx(_TimeoutSession()), IN_SCOPE, plugins=['xss'], timeout_s=1))
    assert result["success"] is False
    assert "exceeded" in result["error"]


async def test_xray_scan_without_a_session_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTESIN_XRAY_TERMS_ACCEPTED", "1")
    result = json.loads(await xray._xray_scan_impl(_Ctx(None), IN_SCOPE))
    assert "no sandbox session" in result["error"]


async def test_xray_scan_requires_license_acknowledgment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PENTESIN_XRAY_TERMS_ACCEPTED", raising=False)
    session = _FakeSession()
    result = json.loads(await xray._xray_scan_impl(_Ctx(session), IN_SCOPE, plugins=['xss']))
    assert result["success"] is False
    assert "accepts its license and disclaimer" in result["error"]
    assert session.calls == []


async def test_bypass_probes_are_labelled_and_off_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTESIN_XRAY_TERMS_ACCEPTED", "1")

    class _ProbeSession(_FakeSession):
        async def exec(self, *argv: str, **_kwargs: Any) -> _Result:
            self.calls.append(tuple(str(a) for a in argv))
            is_curl = bool(argv and argv[0] == "curl")
            is_baseline = is_curl and "-H" not in argv
            if is_curl:
                return _Result(stdout="403" if is_baseline else "200")
            return _Result()

    session = _ProbeSession()
    await xray._xray_scan_impl(_Ctx(session), IN_SCOPE, plugins=['xss'])
    assert not any(call[0] == "curl" for call in session.calls)

    session = _ProbeSession()
    result = json.loads(await xray._xray_scan_impl(_Ctx(session), IN_SCOPE, plugins=['xss'], bypass_403=True))
    probes = [f for f in result["findings"] if f["plugin"] == "403-bypass"]
    assert probes, "expected labelled bypass probes"
    assert all(f["severity"] == "info" for f in probes)
    assert all("status_code" in f for f in probes)


def test_the_runs_own_scan_targets_satisfy_the_scope_check() -> None:
    """The canonical target list must be usable by the scope check as-is.

    It used to carry ``/workspace/<subdir>`` for source targets, which made
    every live target look out of scope. Nothing in the tool could detect that,
    so the contract is asserted here against the real builder.
    """
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {
                    "target_url": IN_SCOPE,
                    "workspace_subdir": "app.example.com",
                },
                "original": IN_SCOPE,
            }
        ]
    }
    built = build_scan_targets(scan_config)
    assert built == [IN_SCOPE]

    url, error = xray._validate_target(IN_SCOPE, built)
    assert error is None, f"a run's own target must pass its own scope check: {error}"
    assert url == IN_SCOPE


async def test_xray_scan_reads_a_report_from_the_real_async_read_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTESIN_XRAY_TERMS_ACCEPTED", "1")
    """A report on disk must come back as findings, not silently as zero."""
    report = json.dumps({"plugin": "xss", "severity": "medium", "target": {"url": IN_SCOPE + "/p"}})
    session = _FakeSession(report=report)
    result = json.loads(await xray._xray_scan_impl(_Ctx(session), IN_SCOPE, plugins=['xss']))
    assert result["count"] == 1
    assert "note" not in result, "a readable report must not be reported as 'no findings'"


def test_xray_scan_is_registered_for_every_agent() -> None:
    assert xray.xray_scan in factory._BASE_TOOLS
