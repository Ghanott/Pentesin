"""Scan bootstrap shared by the CLI entry point and the TUI setup flow.

Target resolution, run preparation, model preflight, and start-of-run
telemetry live here so ``pentesin.interface.main`` (the CLI) and
``pentesin.interface.tui.runtime`` (interactive setup) depend on one module
instead of each other. Everything raises ordinary exceptions; rendering
errors and exiting the process is the caller's job.
"""

from __future__ import annotations

import asyncio
import logging
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pentesin.config import Settings, codex, load_settings
from pentesin.core.paths import run_dir_for
from pentesin.interface.utils import (
    check_mountable_dir,
    derive_local_base_name,
    generate_run_name,
    infer_target_type,
    is_whitebox_scan,
    read_target_list_file,
    reassign_workspace_subdirs,
    rewrite_localhost_targets,
)
from pentesin.telemetry import posthog, scarf
from pentesin.utils.api_spec import (
    SpecParseError,
    classify_spec,
    fetch_postman_collection,
    fetch_postman_environment,
    load_spec,
    spec_base_urls,
    spec_operations,
    spec_title,
)


if TYPE_CHECKING:
    import argparse

    from agents.models.interface import Model

logger = logging.getLogger(__name__)

HOST_GATEWAY_HOSTNAME = "host.docker.internal"


class ModelConnectionError(RuntimeError):
    """An ordinary model preflight failure, annotated with its model route."""

    def __init__(self, model_name: str, cause: BaseException) -> None:
        super().__init__(str(cause))
        self.model_name = model_name


def _first_non_ascii(value: str) -> tuple[int, str] | None:
    for position, char in enumerate(value):
        if ord(char) > 0x7F:
            return position, char
    return None


def _header_candidates(
    prefix: str, model: str | None, api_key: str | None, extra_headers: dict[str, str] | None
) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if api_key and not codex.subscription_model(model):
        candidates.append((f"{prefix}LLM_API_KEY", api_key))
    for header, value in (extra_headers or {}).items():
        candidates.append((f"{prefix}LLM_EXTRA_HEADERS header name {header!r}", header))
        candidates.append((f"{prefix}LLM_EXTRA_HEADERS value for {header!r}", value))
    return candidates


def check_header_safe_credentials(settings: Settings) -> None:
    llm = settings.llm
    dedupe = settings.dedupe
    candidates = _header_candidates("", llm.model, llm.api_key, llm.extra_headers)
    if dedupe.model:
        candidates += _header_candidates(
            "DEDUPE_", dedupe.model, (dedupe.api_key or "").strip(), dedupe.extra_headers
        )
    for setting, value in candidates:
        found = _first_non_ascii(value)
        if found is None:
            continue
        position, char = found
        raise ValueError(
            f"{setting} contains a character that cannot be sent in an HTTP header: "
            f"U+{ord(char):04X} ({unicodedata.name(char, 'unnamed character')}) "
            f"at position {position + 1} of {len(value)}. Re-enter the value without it."
        )


async def preflight_model_connection(
    model_name: str,
    *,
    settings: Settings | None = None,
) -> None:
    """Verify the configured model route before starting a scan."""
    from pentesin.config.models import PentesinProvider, configure_sdk_model_defaults

    resolved_settings = load_settings() if settings is None else settings
    check_header_safe_credentials(resolved_settings)
    configure_sdk_model_defaults(resolved_settings)
    model = PentesinProvider().get_model(model_name)
    await preflight_request(
        model,
        model_name=model_name,
        extra_headers=resolved_settings.llm.extra_headers,
        extra_body=resolved_settings.llm.extra_body,
        timeout=resolved_settings.llm.preflight_timeout,
        api_base_setting="LLM_API_BASE",
    )


async def preflight_request(
    model: Model,
    *,
    model_name: str,
    extra_headers: dict[str, str] | None,
    extra_body: dict[str, Any] | None,
    timeout: int,
    api_base_setting: str,
) -> None:
    """Send one tiny request to ``model`` and fail if it does not answer in ``timeout`` seconds.

    ``api_base_setting`` names the environment variable that points at this
    model's endpoint, so the timeout message sends the user to the right one.
    """
    from agents.models.interface import ModelTracing

    from pentesin.core.inputs import make_model_settings

    request_settings = make_model_settings(
        None,
        model_name=model_name,
        request_timeout=timeout,
        prompt_cache=False,
        extra_headers=extra_headers,
        extra_body=extra_body,
        has_tools=False,
    )
    try:
        await asyncio.wait_for(
            model.get_response(
                system_instructions="You are a helpful assistant.",
                input="Reply with just 'OK'.",
                model_settings=request_settings,
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ),
            timeout=timeout,
        )
    except TimeoutError:
        raise TimeoutError(
            f"{model_name} did not answer within {timeout}s (LLM_PREFLIGHT_TIMEOUT). "
            f"Check {api_base_setting} and that the endpoint is reachable."
        ) from None


def build_targets_info(args: argparse.Namespace) -> None:
    """Populate ``args.targets_info`` from target/target-list inputs.

    Raises :class:`ValueError` with a user-facing message on any bad input so
    callers can surface it via ``parser.error`` (CLI) or a console panel (home
    page).
    """
    args.targets_info = []
    targets = list(args.target or [])
    for target_list_path in args.target_list or []:
        targets.extend(read_target_list_file(target_list_path))

    for target in targets:
        try:
            target_type, target_dict = infer_target_type(target)
        except ValueError as e:
            raise ValueError(f"Invalid target '{target}': {e}") from None

        display_target = target
        if target_type == "api_spec":
            resolve_api_spec(target, target_dict)
            # Do not persist the host filesystem path or Postman collection ID.
            display_target = str(target_dict.get("spec_title") or "API")
        args.targets_info.append(
            {"type": target_type, "details": target_dict, "original": display_target}
        )

    reassign_workspace_subdirs(args.targets_info)
    rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)


def resolve_api_spec(target: str, details: dict[str, Any]) -> None:
    """Parse the API contract on the host; persist only sanitized endpoint metadata."""
    settings = load_settings()
    source = str(details.get("source") or "")
    extra_variables: dict[str, str] | None = None
    raw: dict[str, Any]
    if source == "postman_api":
        collection = fetch_postman_collection(
            str(details.get("collection_uid") or ""),
            settings.integrations.postman_api_key or "",
        )
        if environment_uid := str(details.get("environment_uid") or ""):
            extra_variables = fetch_postman_environment(
                environment_uid,
                settings.integrations.postman_api_key or "",
            )
        raw = collection
    else:
        try:
            raw = load_spec(str(details.get("target_spec") or target))
        except SpecParseError as exc:
            raise ValueError(f"Invalid API specification '{target}': {exc}") from None

    try:
        base_urls = spec_base_urls(raw, extra_variables=extra_variables)
        operations = spec_operations(raw, extra_variables=extra_variables)
    except SpecParseError as exc:
        raise ValueError(f"Invalid API specification '{target}': {exc}") from None

    if not operations:
        raise ValueError(f"API specification '{target}' declares no HTTP operations to test.")
    if not base_urls:
        raise ValueError(
            f"API specification '{target}' declares no resolvable absolute HTTP(S) server."
        )

    # Persist only a bounded contract map. Never keep the host path, collection
    # UID, query/body values, API key, or fetched Postman environment values.
    details.clear()
    details.update(
        {
            "spec_schema_version": 1,
            "spec_format": str(classify_spec(raw) or "api"),
            "spec_title": spec_title(raw),
            "base_urls": base_urls[:100],
            "base_urls_truncated": len(base_urls) > 100,
            "operations": operations[:250],
            "operations_truncated": len(operations) > 250,
        }
    )


def prepare_run(args: argparse.Namespace) -> None:
    """Resolve the run name and persist state.

    Shared by the CLI startup path and the interactive TUI setup phase (once the
    user has supplied a target via ``/target``). Mutates *args* in place and
    raises :class:`ValueError` on any preparation failure.

    Black-box-only: no repository clone, source staging, or diff scope. The only
    local input left is an explicitly attached workspace mount.
    """
    args.run_name = args.resume or generate_run_name(args.targets_info)

    if args.resume:
        return

    args.local_sources = []
    args.diff_scope = {"active": False}

    attach_workspace_mount(args)
    _persist_run_record(args)


def attach_workspace_mount(args: argparse.Namespace) -> None:
    """Expose ``args.workspace_mount`` to the sandbox without making it a target.

    A workspace mount is a directory the agent works in, not something to test:
    it stays out of ``targets_info``, so it carries no authorized scope, and it
    is attached after diff-scope resolution so it contributes no diff context.
    The instruction is the only source of truth for what to do with it.
    """
    mount = getattr(args, "workspace_mount", None)
    if not mount:
        return
    check_mountable_dir(Path(mount).expanduser())
    args.workspace_subdir = derive_local_base_name(mount)
    local_sources = list(getattr(args, "local_sources", None) or [])
    local_sources.append(
        {
            "source_path": mount,
            "workspace_subdir": args.workspace_subdir,
            "protect_metadata": True,
        }
    )
    args.local_sources = local_sources


def telemetry_start(args: argparse.Namespace) -> None:
    model = load_settings().llm.model
    kwargs = {
        "model": model,
        "auth_mode": codex.auth_mode(model),
        "scan_mode": args.scan_mode,
        "is_whitebox": is_whitebox_scan(args.targets_info),
        "interactive": not args.non_interactive,
        "has_instructions": bool(args.instruction),
    }
    posthog.start(**kwargs)
    scarf.start(**kwargs)


def _persist_run_record(args: argparse.Namespace) -> None:
    from pentesin.report.writer import write_run_record

    run_dir = run_dir_for(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_record = {
        "run_id": args.run_name,
        "run_name": args.run_name,
        "status": "running",
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "auth_mode": codex.auth_mode(load_settings().llm.model),
        "targets_info": args.targets_info,
        "scan_mode": args.scan_mode,
        "instruction": args.instruction,
        # Kept apart from instruction, which carries the diff-scope preamble: the
        # transcript replays this as the user's opening message.
        "user_instruction": getattr(args, "user_instruction", None),
        "non_interactive": args.non_interactive,
        "local_sources": getattr(args, "local_sources", []),
        # Persisted so --resume places the same workspace files again.
        "workspace_files": getattr(args, "workspace_files", []),
        # Persisted so --resume can remount the workspace: it is not a target,
        # so it cannot be rebuilt from targets_info.
        "workspace_mount": getattr(args, "workspace_mount", None),
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scope_mode": args.scope_mode,
        "diff_base": args.diff_base,
    }
    write_run_record(run_dir, run_record)
