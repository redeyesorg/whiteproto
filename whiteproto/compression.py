"""Compression wrappers."""
import enum
import zstd  # type: ignore

from whiteproto.utils import cpu_bound_async  # type: ignore


class CompressionMode(enum.Enum):
    """Compression mode."""

    ENABLED = 1
    DISABLED = 2


@cpu_bound_async
def compress(data: bytes) -> bytes:
    """Compress data."""
    if not data:
        return b""
    return zstd.compress(data)  # type: ignore


@cpu_bound_async
def decompress(data: bytes) -> bytes:
    """Decompress data."""
    if not data:
        return b""
    return zstd.decompress(data)  # type: ignore
