"""Local web viewer for pentesin runs.

Serves a prebuilt single-page app that renders a run (live or finished) read
directly from the run's on-disk files. No cloud dependency, no file picker.
"""

from __future__ import annotations

from pentesin.interface.viewer.server import serve


__all__ = ["serve"]
