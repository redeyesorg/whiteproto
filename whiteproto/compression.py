"""Compression wrappers."""
import enum

import zstd  # type: ignore

from whiteproto.async_executor import cpu_bound_async  # type: ignore


class CompressionMode(enum.Enum):
    """Compression mode."""

    ENABLED = 1
    DISABLED = 2


@cpu_bound_async
def compress(data: bytes) -> bytes:
    """Compress data.

    Args:
        data: Data to compress

    Returns:
        Compressed data
    """
    if not data:
        return b""
    return zstd.compress(data)  # type: ignore


@cpu_bound_async
def decompress(data: bytes) -> bytes:
    """Decompress data.

    Args:
        data: Data to decompress

    Returns:
        Decompressed data
    """
    if not data:
        return b""
    return zstd.decompress(data)  # type: ignore
