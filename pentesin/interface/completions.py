"""Shell completion scripts for the Pentesin CLI."""

from __future__ import annotations

import sys
from typing import Any

from pentesin.interface.terminal_text import has_terminal_control, sanitize_terminal_text

_ROOT_COMMANDS = ("auth", "view", "completions", "completion")


def run_completions(argv: list[str]) -> int:
    """Print a shell integration script or hidden completion candidates."""
    if argv and argv[0] == "--candidates":
        for candidate in completion_candidates(argv[1:]):
            sys.stdout.write(candidate + "\n")
        return 0
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(
            "Usage: pentesin completions <zsh|bash|fish>\n\n"
            "Enable tab completion for the current shell:\n"
            "  zsh:  source <(pentesin completions zsh)\n"
            "  bash: source <(pentesin completions bash)\n"
            "  fish: pentesin completions fish | source\n"
        )
        return 0
    shell = argv[0].lower()
    generator = {"zsh": _zsh_script, "bash": _bash_script, "fish": _fish_script}.get(shell)
    if generator is None:
        sys.stderr.write(
            f"Unknown shell: {sanitize_terminal_text(shell)}. Choose zsh, bash, or fish.\n"
        )
        return 2
    sys.stdout.write(generator())
    return 0


def completion_candidates(words: list[str]) -> list[str]:
    """Return Pentesin root-subcommand candidates."""
    prior, current = _split_cursor(words)
    candidates = _matching(_ROOT_COMMANDS, current) if not prior else []
    return [candidate for candidate in candidates if not has_terminal_control(candidate)]


def _split_cursor(words: list[str]) -> tuple[list[str], str]:
    return (words[:-1], words[-1]) if words else ([], "")


def _matching(candidates: Any, prefix: str) -> list[str]:
    return sorted({str(candidate) for candidate in candidates if str(candidate).startswith(prefix)})


def _zsh_script() -> str:
    return r"""#compdef pentesin
_pentesin() {
  local -a candidates
  candidates=("${(@f)$($words[1] completions --candidates "${words[@]:2}")}")
  _describe 'pentesin' candidates
}
compdef _pentesin pentesin
"""


def _bash_script() -> str:
    return r"""_pentesin_completion() {
  local -a candidates
  local candidate
  while IFS= read -r candidate; do candidates+=("$candidate"); done \
    < <(pentesin completions --candidates "${COMP_WORDS[@]:1:$COMP_CWORD}")
  COMPREPLY=("${candidates[@]}")
}
complete -F _pentesin_completion pentesin
"""


def _fish_script() -> str:
    return r"""function __pentesin_candidates
  set -l words (commandline -opc)
  set -e words[1]
  command pentesin completions --candidates $words (commandline -ct)
end
complete -c pentesin -f -a '(__pentesin_candidates)'
"""
