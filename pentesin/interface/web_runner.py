"""Authenticated loopback worker for the private web dashboard."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing

from pentesin.config import load_settings
from pentesin.config.settings import DEFAULT_MAX_TURNS
from pentesin.core.agents import AgentCoordinator
from pentesin.core.paths import run_dir_for, runtime_state_dir
from pentesin.core.runner import run_pentesin_scan
from pentesin.interface.tui.live_view import TuiLiveView
from pentesin.interface.utils import infer_target_type
from pentesin.report.state import ReportState, set_global_report_state


if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)
HEARTBEAT_SECONDS = 15
MAX_ARTIFACT_BYTES = 1_000_000
_SECRET_KEY = re.compile(r"api[_-]?key|token|secret|password|credential", re.IGNORECASE)
ARTIFACT_NAMES = (
    "penetration_test_report.md",
    "vulnerabilities.json",
    "findings.sarif",
    "coverage.json",
    "report_narratives.json",
)


def validate_base_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid runner base URL") from exc
    if (
        parts.scheme != "http"
        or host not in {"localhost", "127.0.0.1", "::1"}
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ValueError("runner base URL must be an HTTP loopback URL")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit(("http", netloc, "", "", ""))


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[redacted]" if _SECRET_KEY.search(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _clean_env(*, control_url: str, control_token: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not _SECRET_KEY.search(key)}
    env["PENTESIN_APP_URL"] = control_url
    env["PENTESIN_RUNNER_TOKEN"] = control_token
    return env


def _safe_job(job: Any) -> dict[str, Any]:
    if not isinstance(job, dict) or job.get("kind") not in {"scan", "model_test"}:
        raise ValueError("unsupported runner job")
    job_id = job.get("id")
    if isinstance(job_id, bool) or not (
        (isinstance(job_id, int) and job_id > 0)
        or (
            isinstance(job_id, str)
            and job_id.isascii()
            and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", job_id)
        )
    ):
        raise ValueError("invalid job id")
    if not isinstance(job.get("lease_token"), str) or not 0 < len(job["lease_token"]) <= 512:
        raise ValueError("invalid job lease")
    if not isinstance(job.get("profile"), dict):
        raise TypeError("invalid job profile")
    if job["kind"] == "scan" and (
        not isinstance(job.get("target"), str) or not 0 < len(job["target"]) <= 2048
    ):
        raise ValueError("invalid scan target")
    return job


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _post_json(
    url: str, token: str, body: dict[str, Any] | None = None, *, timeout: float = 15
) -> dict[str, Any]:
    parts = urlsplit(url)
    validate_base_url(urlunsplit((parts.scheme, parts.netloc, "", "", "")))
    request = urllib.request.Request(  # noqa: S310
        url,
        data=json.dumps(body or {}).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("runner response exceeds size limit")
    parsed = json.loads(raw) if raw else {}
    if not isinstance(parsed, dict):
        raise TypeError("invalid runner response")
    return parsed


async def _run_model_test(job: dict[str, Any]) -> dict[str, Any]:
    from pentesin.config.models import PentesinProvider  # noqa: PLC0415

    profile = job.get("profile")
    model_name = profile.get("model") if isinstance(profile, dict) else None
    if not isinstance(model_name, str) or not model_name.strip() or len(model_name) > 500:
        raise ValueError("invalid model profile: model is required")
    started = time.monotonic()
    model = PentesinProvider(
        api_key=profile.get("api_key"), base_url=profile.get("api_base")
    ).get_model(model_name)
    response = await model.get_response(
        system_instructions=None,
        input="test",
        model_settings=ModelSettings(tool_choice=None),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )
    ok = any(
        getattr(chunk, "text", "")
        for item in response.output
        for chunk in getattr(
            item, "content", getattr(getattr(item, "raw_item", None), "content", [])
        )
    )
    return {
        "ok": bool(ok),
        "connection": True,
        "latency_ms": int((time.monotonic() - started) * 1000),
        "error": None if ok else "Model returned no text response",
    }


async def _model_test_child() -> int:
    try:
        profile = json.loads(sys.stdin.buffer.read(1024 * 1024 + 1))
        if not isinstance(profile, dict):
            raise TypeError("invalid model profile")  # noqa: TRY301
        result = await asyncio.wait_for(_run_model_test({"profile": profile}), timeout=60)
    except Exception:
        logger.exception("Model test failed")
        result = {"ok": False, "connection": False, "latency_ms": 0, "error": "Model test failed"}
    sys.stdout.write(json.dumps(_redact(result)) + "\n")
    return 0


def _upload_artifacts(base: str, token: str, job: dict[str, Any], run_dir: str | Path) -> None:
    root = Path(run_dir).resolve()
    for name in ARTIFACT_NAMES:
        artifact = root / name
        try:
            if not artifact.is_file() or artifact.stat().st_size > MAX_ARTIFACT_BYTES:
                continue
            content = artifact.read_bytes()
            if len(content) > MAX_ARTIFACT_BYTES:
                continue
        except OSError:
            continue
        try:
            _post_json(
                f"{base}/api/internal/runner/v1/scans/{job['id']}/artifacts/{name}",
                token,
                {
                    "lease_token": job["lease_token"],
                    "content_base64": base64.b64encode(content).decode("ascii"),
                },
            )
        except urllib.error.HTTPError as exc:
            if exc.code != 409:
                raise
            logger.warning("Artifact already stored or lease replaced: %s", name)


def _completion_path(job: dict[str, Any]) -> Path:
    return runtime_state_dir(run_dir_for(f"web-{job['id']}")) / "pending-completion.json"


def _save_completion(base: str, job: dict[str, Any], payload: dict[str, Any]) -> Path:
    path = _completion_path(job)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"base": base, "id": job["id"], "payload": payload}, handle)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)
    return path


async def _flush_completions(base: str, token: str) -> bool:
    root = run_dir_for("web-placeholder").parent
    for path in root.glob("web-*/.state/pending-completion.json"):
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
            if saved["base"] != base:
                continue
            job = _safe_job(
                {
                    "id": saved["id"],
                    "lease_token": saved["payload"]["lease_token"],
                    "kind": "model_test",
                    "profile": {},
                }
            )
            await asyncio.to_thread(
                _post_json,
                f"{base}/api/internal/runner/v1/scans/{job['id']}/heartbeat",
                token,
                saved["payload"],
            )
            await asyncio.to_thread(_upload_artifacts, base, token, job, path.parent.parent)
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                logger.warning("Discarding completion rejected by lease fencing")
                path.unlink()
                continue
            logger.exception("Pending completion delivery failed")
            return False
        except Exception:
            logger.exception("Pending completion delivery failed")
            return False
        path.unlink()
    return True


async def _supervise_scan(  # noqa: PLR0915
    scan: Callable[..., Any],
    coordinator: Any,
    live: TuiLiveView,
    report: Any,
    job: dict[str, Any],
    *,
    base: str,
    token: str,
) -> dict[str, Any]:
    stop = asyncio.Event()
    operator_stopped = False
    scan_task: asyncio.Task[Any] | None = None
    event_prefix = hashlib.sha256(job["lease_token"].encode()).hexdigest()[:16]
    last_events: dict[str, int] = {}
    last_errors: dict[str, str] = {}

    def capture_event(agent_id: str, event: Any) -> None:
        live.ingest_sdk_event(agent_id, event)

    async def heartbeat(status: str | None = None) -> None:  # noqa: PLR0912
        nonlocal operator_stopped
        parent_of, statuses, names, errors = await coordinator.graph_snapshot()
        for agent_id, error in errors.items():
            if error and last_errors.get(agent_id) != error:
                live.record_agent_error(agent_id, error)
        last_errors.clear()
        last_errors.update(errors)
        agents = [
            {
                "id": aid,
                "parent_id": parent_of.get(aid),
                "name": names.get(aid, aid),
                "status": str(state),
            }
            for aid, state in statuses.items()
        ]
        events = []
        for event in live.events:
            source_id = f"{event_prefix}:{event.get('id', '')}"
            version = int(event.get("version", 0))
            if last_events.get(source_id, -1) >= version:
                continue
            events.append(
                {
                    "source_id": source_id,
                    "agent_id": event.get("agent_id"),
                    "type": event.get("type", "chat"),
                    "version": version,
                    "data": event.get("data", {}),
                }
            )
            if len(events) == 1000:
                break
        payload: dict[str, Any] = {
            "lease_token": job["lease_token"],
            "agents": agents[:500],
            "events": events,
            "findings": [
                {"action": "upsert", **item}
                for item in report.vulnerability_reports
                if isinstance(item, dict)
            ][:1000],
        }
        if status:
            payload["status"] = status
        pending = _save_completion(base, job, payload) if status else None
        try:
            response = await asyncio.to_thread(
                _post_json,
                f"{base}/api/internal/runner/v1/scans/{job['id']}/heartbeat",
                token,
                payload,
            )
        except Exception:
            if pending is None:
                raise
            logger.exception("Scan finished locally; completion delivery pending")
            return
        last_events.update({event["source_id"]: event["version"] for event in events})
        for command in response.get("commands", []):
            cmd_id = command.get("id") if isinstance(command, dict) else None
            if isinstance(cmd_id, bool) or not isinstance(cmd_id, (int, str)) or not str(cmd_id):
                continue
            if command.get("type") == "stop":
                operator_stopped = True
                if scan_task is not None:
                    scan_task.cancel()
                return
            aid = command.get("agent_id")
            if aid not in statuses:
                continue
            sent = bool(
                isinstance(aid, str)
                and await coordinator.send(
                    aid, {"from": "user", "content": str(command.get("message") or "")[:10000]}
                )
            )
            await asyncio.to_thread(
                _post_json,
                f"{base}/api/internal/runner/v1/scans/{job['id']}/commands/{command['id']}/ack",
                token,
                {"lease_token": job["lease_token"], "status": "delivered" if sent else "failed"},
            )

    async def heartbeat_loop() -> None:
        while not stop.is_set():
            try:
                await heartbeat()
            except Exception:
                logger.exception("Runner heartbeat failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=HEARTBEAT_SECONDS)

    scan_task = asyncio.create_task(scan(capture_event))
    task = asyncio.create_task(heartbeat_loop())
    status = "completed"
    try:
        await scan_task
    except asyncio.CancelledError:
        if not operator_stopped:
            raise
        status = "stopped"
    except Exception:
        logger.exception("Scan failed")
        status = "failed"
    finally:
        stop.set()
        await task
    _, agent_statuses, _, _ = await coordinator.graph_snapshot()
    if status == "completed" and any(
        state in {"failed", "crashed"} for state in agent_statuses.values()
    ):
        status = "failed"
    report.cleanup(status=status)
    await heartbeat(status)
    return {"status": status}


async def _execute_job(base: str, token: str, job: dict[str, Any]) -> None:
    job = _safe_job(job)
    endpoint = f"{base}/api/internal/runner/v1/scans/{job['id']}/heartbeat"
    if job["kind"] == "model_test":
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "pentesin.interface.web_runner",
            "--model-test-child",
            env=_clean_env(control_url=base, control_token=token),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            output, _ = await asyncio.wait_for(
                process.communicate(json.dumps(job["profile"]).encode()), timeout=75
            )
            result = json.loads(output[:65536]) if process.returncode == 0 else {}
            if not isinstance(result, dict):
                result = {}
        except TimeoutError:
            process.kill()
            await process.communicate()
            result = {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            result = {}
        result = result or {
            "ok": False,
            "connection": False,
            "latency_ms": 0,
            "error": "Model test process failed",
        }
        _post_json(
            endpoint,
            token,
            {
                "lease_token": job["lease_token"],
                "status": "completed" if result.get("ok") else "failed",
                "test_result": _redact(result),
                "error": result.get("error"),
            },
        )
        return

    profile = job["profile"]
    settings = load_settings()
    settings.llm.model = profile.get("model")
    settings.llm.api_key = profile.get("api_key")
    settings.llm.api_base = profile.get("api_base")
    target_type, details = infer_target_type(job["target"])
    if target_type not in {"web_application", "ip_address"}:
        raise ValueError("web runner accepts live targets only")
    scan_id = f"web-{job['id']}"
    raw_mode = job.get("mode") or "standard"
    scan_mode = "standard" if raw_mode == "quick" else raw_mode
    scan_config = {
        "scan_id": scan_id,
        "run_name": scan_id,
        "targets": [{"original": job["target"], "type": target_type, "details": details}],
        "user_instructions": job.get("instruction") or "",
        "scan_mode": scan_mode,
        "context_mode": job.get("context_mode") is True,
    }
    if job.get("resume") is True:
        state_dir = runtime_state_dir(run_dir_for(scan_id))
        if not all((state_dir / name).is_file() for name in ("agents.json", "agents.db")):
            raise ValueError("Cannot resume: agent checkpoint is missing on this runner")
    report = ReportState(scan_id)
    if job.get("resume") is True:
        report.hydrate_from_run_dir()
    report.set_scan_config(scan_config)
    report.save_run_data()
    set_global_report_state(report)
    coordinator = AgentCoordinator()

    async def scan(event_sink: Callable[[str, Any], None]) -> None:
        await run_pentesin_scan(
            scan_config=scan_config,
            scan_id=scan_id,
            image=settings.runtime.image,
            local_sources=[],
            extra_files=[],
            coordinator=coordinator,
            interactive=True,
            max_turns=DEFAULT_MAX_TURNS,
            max_budget_usd=job.get("max_budget"),
            event_sink=event_sink,
            mcp_connection_requests=[],
        )

    await _supervise_scan(scan, coordinator, TuiLiveView(), report, job, base=base, token=token)
    await _flush_completions(base, token)


async def run_worker(base_url: str, token: str, *, once: bool = False) -> int:
    try:
        base = validate_base_url(base_url)
        if not isinstance(token, str) or not token.strip() or len(token) > 4096:
            raise ValueError("invalid runner token")  # noqa: TRY301
    except ValueError:
        logger.exception("Invalid runner configuration")
        return 2
    while True:
        try:
            if not await _flush_completions(base, token):
                if once:
                    return 1
                await asyncio.sleep(HEARTBEAT_SECONDS)
                continue
            response = await asyncio.to_thread(
                _post_json, f"{base}/api/internal/runner/v1/claim", token
            )
            job = response.get("job")
            if job is not None:
                try:
                    await _execute_job(base, token, job)
                except Exception:
                    logger.exception("Runner job failed")
                    with contextlib.suppress(Exception):
                        safe = _safe_job(job)
                        await asyncio.to_thread(
                            _post_json,
                            f"{base}/api/internal/runner/v1/scans/{safe['id']}/heartbeat",
                            token,
                            {
                                "lease_token": safe["lease_token"],
                                "status": "failed",
                                "error": "Runner job failed",
                            },
                        )
        except Exception:
            logger.exception("Runner control-plane request failed")
            if once:
                return 1
        if once:
            return 0
        await asyncio.sleep(HEARTBEAT_SECONDS)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the authenticated Pentesin web worker")
    parser.add_argument(
        "--base-url", default=os.environ.get("PENTESIN_APP_URL", "http://127.0.0.1:8000")
    )
    parser.add_argument("--token", default=os.environ.get("PENTESIN_RUNNER_TOKEN", ""))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--model-test-child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.model_test_child:
        return asyncio.run(_model_test_child())
    return asyncio.run(run_worker(args.base_url, args.token, once=args.once))


if __name__ == "__main__":
    raise SystemExit(main())
