"""Run directory path helpers."""

from __future__ import annotations

from pathlib import Path


RUNS_DIR_NAME = "pentesin_runs"
LEGACY_RUNS_DIR_NAME = "pentesin_runs"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    current = base / RUNS_DIR_NAME / run_name
    legacy = base / LEGACY_RUNS_DIR_NAME / run_name
    if current.exists() or not legacy.exists():
        return current
    return legacy


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def runs_base_dir(*, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME


def runs_base_dirs(*, cwd: Path | None = None) -> tuple[Path, ...]:
    """Return current and legacy run roots, without moving prior user data."""
    base = cwd or Path.cwd()
    roots = (base / RUNS_DIR_NAME, base / LEGACY_RUNS_DIR_NAME)
    return tuple(root for root in roots if root.is_dir())


def latest_run_dir(*, cwd: Path | None = None) -> Path | None:
    candidates = [
        child
        for base in runs_base_dirs(cwd=cwd)
        for child in base.iterdir()
        if run_record_path(child).is_file()
    ]
    if not candidates:
        return None
    # run.json is rewritten on status/end changes, so its mtime tracks activity
    # more reliably than the directory mtime (a live run sorts to the top).
    return max(candidates, key=lambda child: run_record_path(child).stat().st_mtime)
