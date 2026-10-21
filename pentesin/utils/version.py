"""Package version lookup with migration compatibility."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def get_package_version() -> str:
    """Read Pentesin's installed version, falling back to legacy pentesin installs."""
    try:
        return version("pentesin-agent")
    except PackageNotFoundError:
        try:
            return version("pentesin-agent")
        except PackageNotFoundError:
            return "unknown"
