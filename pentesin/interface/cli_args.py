"""Command-line argument parsing for the ``pentesin`` scan entrypoint."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from pentesin.config import apply_config_override
from pentesin.config.settings import DEFAULT_MAX_TURNS
from pentesin.core.paths import RUNS_DIR_NAME, run_dir_for, runtime_state_dir
from pentesin.interface.scan_setup import (
    attach_workspace_mount,
    build_targets_info,
    resolve_api_spec,
)
from pentesin.interface.update_check import self_update
from pentesin.interface.utils import (
    reassign_workspace_subdirs,
    resolve_workspace_files,
    rewrite_localhost_targets,
    validate_config_file,
)
from pentesin.report.runs import list_run_summaries
from pentesin.utils.api_spec import spec_base_urls
from pentesin.utils.version import get_package_version


# Severities ``--fail-on`` accepts, most severe first.
FAIL_ON_SEVERITIES = ("critical", "high", "medium", "low", "info")


def get_version() -> str:
    return get_package_version()


def _positive_budget(value: str) -> float:
    try:
        budget = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    import math

    if not math.isfinite(budget) or budget <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than 0")
    return budget


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be an integer greater than 0")
    return parsed


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pentesin Black-Box Web and API Pentesting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This build is black-box only: target live URLs, domains, IPs, or API contracts
(OpenAPI/Swagger/Postman).
API specs provide endpoint maps and authorize their declared HTTP(S) servers.
Source code and Git repositories are rejected.

Examples:
  # Web application penetration test
  pentesin--target https://example.com

  # Domain penetration test
  pentesin--target example.com

  # IP address penetration test
  pentesin--target 192.168.1.42

  # Black-box API test; contract servers become authorized targets
  pentesin--target ./openapi.yaml
  pentesin--target ./collection.postman_collection.json
  pentesin--target "postman://<collection-id>?env=<environment-id>"

  # Multiple live targets (only test what you are authorized to test)
  pentesin--target https://staging.example.com --target https://prod.example.com

  # Targets from a file, one target per non-empty, non-comment line
  pentesin--target-list ./targets.txt

  # Custom instructions (inline)
  pentesin--target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  pentesin--target example.com --instruction-file ./instructions.txt
  pentesin--target https://app.com --instruction-file /path/to/detailed_instructions.md

  # Extra files placed in the sandbox workspace, e.g. a wordlist or auth header notes
  pentesin--target example.com --workspace-file ./wordlist.txt
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"pentesin{get_version()}",
    )

    parser.add_argument(
        "--update",
        action="store_true",
        help="Update pentesinto the latest version and exit. Self-updates the "
        "standalone binary install; for pip/pipx/uv installs, prints the "
        "matching upgrade command instead.",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="Live target (URL/domain/IP) or OpenAPI/Swagger/Postman API contract. "
        "API contracts add declared HTTP(S) servers to scope; source directories and Git "
        "repositories are rejected. Only test targets you are authorized to test. "
        "Can be specified multiple times for multi-target scans. "
        "Fresh runs require --target or --target-list.",
    )
    parser.add_argument(
        "--target-list",
        type=str,
        action="append",
        metavar="PATH",
        help="Path to a file containing targets, one per non-empty, non-comment line. "
        "Can be specified multiple times and combined with --target.",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="Path to a file containing detailed custom instructions for the penetration test. "
        "Use this option when you have lengthy or complex instructions saved in a file "
        "(e.g., '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "--workspace-file",
        type=str,
        action="append",
        metavar="PATH[:DEST]",
        help="Place an auxiliary file from this machine into the sandbox workspace before the scan "
        "starts, for example a wordlist or notes (never as a scan target). Repeat the option "
        "for more files. DEST is the path inside /workspace and defaults to the file name "
        "(for example '--workspace-file ./wordlist.txt:lists/wordlist.txt'). Pentesin copies "
        "the file into the sandbox, outside every target directory. The agent can edit the "
        "copy. The file on this machine does not change.",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    parser.add_argument(
        "--fail-on",
        dest="fail_on",
        type=str.lower,
        choices=FAIL_ON_SEVERITIES,
        default=None,
        metavar="SEVERITY",
        help=(
            "Headless mode only: exit 2 only when a finding is at or above this severity "
            "(critical, high, medium, low, info). Lower findings are still written to every "
            "report artifact. A finding with an unrecognized severity always counts. "
            "Default: any finding exits 2."
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "Scan mode: "
            "'quick' for fast CI/CD checks, "
            "'standard' for routine testing, "
            "'deep' for thorough security reviews (default). "
            "Default: deep."
        ),
    )

    # Accepted and ignored: this build has no code targets, so there is no
    # change set to scope a run to. Kept so an existing invocation (and the TUI
    # protocol that carries them) does not break.
    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=argparse.SUPPRESS,
    )

    parser.add_argument("--diff-base", type=str, help=argparse.SUPPRESS)

    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom config file (JSON) to use instead of ~/.pentesin/cli-config.json",
    )

    parser.add_argument(
        "--mcp-config",
        type=str,
        metavar="PATH",
        help="Path to an MCP servers JSON file to use instead of ~/.pentesin/mcp-servers.json.",
    )

    parser.add_argument(
        "--mcp-server",
        dest="mcp_server",
        action="append",
        metavar="NAME",
        help="Use only this MCP connection for the run, by its config name "
        "(repeatable). Every other configured connection is skipped.",
    )

    parser.add_argument(
        "--mcp-exclude",
        dest="mcp_exclude",
        action="append",
        metavar="NAME",
        help="Skip this MCP connection for the run, by its config name (repeatable).",
    )

    parser.add_argument(
        "--max-budget",
        "--max-budget-usd",
        dest="max_budget_usd",
        metavar="USD",
        type=_positive_budget,
        default=None,
        help=(
            "Maximum LLM cost in USD (> 0). The scan stops cleanly when this limit is reached. "
            "Graduated wrap-up warnings are sent to all agents as it is approached."
        ),
    )

    parser.add_argument(
        "--max-turns",
        dest="max_turns",
        metavar="N",
        type=_positive_int,
        default=DEFAULT_MAX_TURNS,
        help=(
            "Maximum turns per agent (> 0, default %(default)s). Each agent is force-stopped "
            "when it reaches this limit, with graduated wrap-up warnings as it is approached."
        ),
    )

    parser.add_argument(
        "-r",
        "--resume",
        type=str,
        nargs="?",
        const="",
        metavar="RUN_NAME",
        help=(
            "Resume a prior scan by its run name (the dir under ./pentesin_runs/). "
            "Picks up the root + every non-terminal subagent's full LLM history "
            "and agent topology. Skips fresh run-name generation. Without a "
            "name, opens a picker of the prior runs."
        ),
    )

    args = parser.parse_args()
    # Startup-resolved state lives alongside the parsed flags. The full schema
    # is established here so downstream code reads attributes directly.
    args.needs_setup = False
    args.resume_picker = False
    args.targets_info = []
    args.local_sources = []
    args.diff_scope = {"active": False}
    args.run_name = None

    if args.config:
        apply_config_override(validate_config_file(args.config))

    if args.mcp_config:
        mcp_config_path = Path(args.mcp_config).expanduser()
        if not mcp_config_path.is_file():
            parser.error(f"--mcp-config file not found: {args.mcp_config}")
        # The MCP loader reads this env var as its config-path override, so
        # setting it here makes the flag win over the default location.
        os.environ["PENTESIN_MCP_CONFIG"] = str(mcp_config_path)

    # The MCP loader reads these as its per-run include/exclude selection.
    if args.mcp_server:
        os.environ["PENTESIN_MCP_ONLY"] = ",".join(args.mcp_server)
    if args.mcp_exclude:
        os.environ["PENTESIN_MCP_EXCLUDE"] = ",".join(args.mcp_exclude)

    if args.update:
        sys.exit(0 if self_update() else 1)

    if args.fail_on and not args.non_interactive and terminal_attached():
        # Without a terminal main() switches to headless anyway, so the
        # flag is only out of place when the TUI would actually open.
        parser.error("--fail-on only applies to headless runs; add -n/--non-interactive.")

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    try:
        args.workspace_files = resolve_workspace_files(getattr(args, "workspace_file", None))
    except ValueError as error:
        parser.error(f"--workspace-file: {error}")

    args.user_explicit_instruction = args.instruction if args.resume is not None else None
    # What the user actually asked for, kept apart from args.instruction because
    # prepare_run prepends the diff-scope preamble to that. This is the text the
    # transcript shows as their opening message.
    args.user_instruction = args.instruction or None

    if args.resume is not None:
        if args.target or args.target_list:
            parser.error(
                "Cannot combine --resume with --target/--target-list. "
                "--resume picks up where the prior run left off, including the "
                "original target list."
            )
        if not args.resume.strip():
            # A bare --resume: main() opens the inline picker of prior runs
            # before anything launches; headless has nobody to pick, so it
            # lists them.
            args.resume = None
            args.resume_picker = True
            if args.non_interactive:
                parser.error(resume_run_list_message("--resume needs a run name in headless mode."))
            if not list_run_summaries():
                parser.error(f"--resume: no runs in ./{RUNS_DIR_NAME} to resume")
            return args
        try:
            load_resume_state(args)
        except ResumeError as exc:
            parser.error(str(exc))
    else:
        if not args.target and not args.target_list:
            if args.non_interactive:
                parser.error(
                    "the following arguments are required: -t/--target or --target-list "
                    "(or use --resume <run_name> to continue a prior scan)"
                )
            # Interactive launch with no target: open the normal TUI on its
            # start screen, where the user gives a target or a bare prompt
            # before the scan starts.
            args.needs_setup = True
            return args

        try:
            build_targets_info(args)
        except ValueError as e:
            parser.error(str(e))

    return args


def terminal_attached() -> bool:
    """Whether the TUI can take over the terminal: a tty on both ends, not dumb."""
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return False
    return all(hasattr(stream, "isatty") and stream.isatty() for stream in (sys.stdin, sys.stdout))


class ResumeError(ValueError):
    """A prior run cannot be resumed as recorded; the message names why."""


def resume_run_list_message(lead: str) -> str:
    """``lead`` followed by the runs that ``--resume <name>`` would accept."""
    runs = list_run_summaries()
    if not runs:
        return f"{lead} There are no runs in ./{RUNS_DIR_NAME}."
    name_width = max(len(run.run_name) for run in runs)
    status_width = max(len(run.status) for run in runs)
    lines = [f"{lead} Runs in ./{RUNS_DIR_NAME}:"]
    lines.extend(
        f"  {run.run_name:<{name_width}}  {run.status:<{status_width}}  "
        f"{run.started_at[:19]:<19}  {run.target}".rstrip()
        for run in runs
    )
    return "\n".join(lines)


def load_resume_state(args: argparse.Namespace) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json.

    Raises :class:`ResumeError` when the run is missing, unreadable, or its
    recorded workspace is gone.
    """
    from pentesin.report.writer import read_run_record

    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    if not state_path.exists():
        raise ResumeError(
            f"--resume {args.resume}: no such run "
            f"(missing {state_path}; remove --resume for a fresh start)"
        )
    try:
        state = read_run_record(run_dir)
    except (RuntimeError, TypeError) as exc:
        raise ResumeError(f"--resume {args.resume}: run.json unreadable: {exc}") from exc

    args.targets_info = state.get("targets_info") or []
    # A target-less run has no targets_info at all. It is driven by its
    # instruction, over a mounted working directory or over nothing when the
    # mount was declined, so either of those is enough to resume it.
    workspace_mount = state.get("workspace_mount") or None
    if not args.targets_info and not workspace_mount and not state.get("user_instruction"):
        raise ResumeError(f"--resume {args.resume}: run.json has no targets_info")

    # Source trees remain unsupported. Legacy API-spec records are upgraded
    # host-side; their raw files are never restored as sandbox mounts.
    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        target_type = target.get("type")
        if target_type in ("local_code", "repository"):
            raise ResumeError(
                f"--resume {args.resume}: run.json records a {target_type!r} source target, "
                "which this black-box-only build does not support. Start a fresh run "
                "against a live URL, domain, IP, or API spec."
            )
        if target_type == "api_spec":
            details = target.get("details") or {}
            if not details.get("operations"):
                spec_path = details.get("target_spec")
                if not spec_path or not Path(str(spec_path)).is_file():
                    raise ResumeError(
                        f"--resume {args.resume}: legacy API spec is missing; start a fresh run "
                        "with the OpenAPI/Swagger/Postman file."
                    )
                try:
                    resolve_api_spec(str(spec_path), details)
                    target["original"] = details.get("spec_title") or "API"
                except ValueError as error:
                    raise ResumeError(f"--resume {args.resume}: {error}") from error
            else:
                # Re-parse from the sanitized inventory: never trust raw legacy
                # `target_spec` paths or previously persisted arbitrary fields.
                operations = details.get("operations")
                if not isinstance(operations, list):
                    raise ResumeError(
                        f"--resume {args.resume}: API spec inventory is invalid; start a fresh run."
                    )
                safe_operations = []
                for operation in operations[:250]:
                    if not isinstance(operation, dict):
                        continue
                    method = str(operation.get("method") or "").upper()
                    path = str(operation.get("path") or "")
                    if method not in {
                        "GET",
                        "PUT",
                        "POST",
                        "DELETE",
                        "OPTIONS",
                        "HEAD",
                        "PATCH",
                        "TRACE",
                    }:
                        continue
                    if not path.startswith("/") or any(
                        ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path
                    ):
                        continue
                    safe_operation: dict[str, Any] = {"method": method, "path": path[:120]}
                    parameters = operation.get("parameters")
                    if isinstance(parameters, list):
                        safe_operation["parameters"] = [
                            {
                                "name": str(param.get("name", ""))[:120],
                                "in": str(param.get("in", ""))[:24],
                            }
                            for param in parameters[:20]
                            if isinstance(param, dict)
                            and param.get("in") in {"path", "query", "header", "cookie"}
                        ]
                    content_types = operation.get("content_types")
                    if isinstance(content_types, list):
                        safe_operation["content_types"] = [
                            str(item)[:100] for item in content_types[:10]
                        ]
                    fields = operation.get("body_fields")
                    if isinstance(fields, list):
                        safe_operation["body_fields"] = [
                            {
                                "name": str(field.get("name", ""))[:120],
                                "type": str(field.get("type", ""))[:40],
                            }
                            for field in fields[:20]
                            if isinstance(field, dict)
                        ]
                    if isinstance(operation.get("auth_required"), bool):
                        safe_operation["auth_required"] = operation["auth_required"]
                    schemes = operation.get("security_schemes")
                    if isinstance(schemes, list):
                        safe_operation["security_schemes"] = [str(s)[:120] for s in schemes[:20]]
                    safe_operations.append(safe_operation)
                bases = details.get("base_urls") or []
                safe_bases = spec_base_urls(
                    {"openapi": "3.0.0", "servers": [{"url": str(base)} for base in bases[:100]]}
                )
                if not safe_bases or not safe_operations:
                    raise ResumeError(
                        f"--resume {args.resume}: API spec inventory/scope is incomplete; "
                        "start a fresh run."
                    )
                title = "".join(
                    ch
                    for ch in str(details.get("spec_title") or "API")
                    if ord(ch) >= 0x20 and ord(ch) != 0x7F
                )[:120]
                target["details"] = {
                    "spec_schema_version": 1,
                    "spec_format": str(details.get("spec_format") or "api")[:20],
                    "spec_title": title,
                    "base_urls": list(dict.fromkeys(safe_bases)),
                    "base_urls_truncated": bool(details.get("base_urls_truncated")),
                    "operations": safe_operations,
                    "operations_truncated": bool(details.get("operations_truncated")),
                }
                target["original"] = title or "API"

    args.targets_info = [target for target in args.targets_info if isinstance(target, dict)]
    rewrite_localhost_targets(args.targets_info, "host.docker.internal")
    # Existing spec-declared hosts are explicit scan scope and survive resume.
    reassign_workspace_subdirs(args.targets_info)

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if not getattr(args, "user_instruction", None):
        args.user_instruction = state.get("user_instruction") or None
    args.local_sources = []
    # Remount the workspace the run was started with. The user already confirmed
    # this directory, so the target mount guard does not apply to it; it only has
    # to still be there.
    args.workspace_mount = workspace_mount

    # Replace the workspace files the run started with, unless this resume names
    # its own. The persisted record is revalidated like a fresh flag, so an
    # edited run.json cannot widen what a resume places. A file deleted between
    # runs is dropped rather than fatal: it is context for the agent, not scope.
    if not getattr(args, "workspace_files", None):
        restored = [
            f"{source_path}:{workspace_path}"
            for workspace_file in state.get("workspace_files") or []
            if isinstance(workspace_file, dict)
            and (source_path := Path(str(workspace_file.get("source_path") or ""))).is_file()
            and (workspace_path := str(workspace_file.get("workspace_path") or ""))
        ]
        try:
            args.workspace_files = resolve_workspace_files(restored)
        except ValueError as error:
            raise ResumeError(f"--resume {args.resume}: invalid workspace file: {error}") from error
    if workspace_mount:
        if not Path(workspace_mount).expanduser().is_dir():
            raise ResumeError(
                f"--resume {args.resume}: the working directory {workspace_mount} "
                f"is missing. Restore it before resuming, or start a fresh run."
            )
        attach_workspace_mount(args)
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode
    agents_path = runtime_state_dir(run_dir) / "agents.json"
    if not agents_path.exists():
        raise ResumeError(
            f"--resume {args.resume}: missing {agents_path}. The run was "
            f"persisted but never reached its first agent snapshot — "
            f"there's nothing to resume from. Pick a fresh --run-name "
            f"or remove --resume to start over with the same targets."
        )
