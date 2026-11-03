"""Autonomous Exploit Chaining (chain-builder) for Pentesin.

Provides systematic A -> B -> C exploit chain hypothesis generation, candidate
selection, and chain linking to elevate low/medium primitives into high/critical
demonstrated impact.
"""

from __future__ import annotations

from pentesin.chain.matrix import (
    CHAIN_PATTERNS,
    ChainCandidate,
    ChainRecipe,
    find_chain_candidates,
)


__all__ = [
    "CHAIN_PATTERNS",
    "ChainCandidate",
    "ChainRecipe",
    "find_chain_candidates",
]
