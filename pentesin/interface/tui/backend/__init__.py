"""Backend bridge for external TUI clients."""

from pentesin.interface.tui.backend.controller import TuiController
from pentesin.interface.tui.backend.server import TuiBackendServer


__all__ = ["TuiBackendServer", "TuiController"]
