import sys
from pathlib import Path


def get_pentesin_resource_path(*parts: str) -> Path:
    frozen_base = getattr(sys, "_MEIPASS", None)
    if frozen_base:
        base = Path(frozen_base) / "pentesin"
        if base.exists():
            return base.joinpath(*parts)

    base = Path(__file__).resolve().parent.parent
    return base.joinpath(*parts)
