"""Smart Recon & Recon Output Compression module for Pentesin.

Provides pattern deduplication, binary asset filtering, and attack surface
prioritization to conserve agent context window without skipping targets.
"""

from __future__ import annotations

from pentesin.recon.compressor import (
    compress_recon_output,
    deduplicate_url_patterns,
    filter_binary_extensions,
    rank_recon_endpoints,
)


__all__ = [
    "compress_recon_output",
    "deduplicate_url_patterns",
    "filter_binary_extensions",
    "rank_recon_endpoints",
]
