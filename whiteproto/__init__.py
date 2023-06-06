"""WhiteProto reference implementation"""

from whiteproto._proto import CloseConnectionReason
from whiteproto.client import open_connection
from whiteproto.compression import CompressionMode
from whiteproto.connection import (
    ConnectionClosedError,
    FragmentationMode,
    WhiteConnection,
)
from whiteproto.server import WhiteServer

__all__ = [
    "open_connection",
    "WhiteServer",
    "WhiteConnection",
    "CloseConnectionReason",
    "FragmentationMode",
    "CompressionMode",
    "ConnectionClosedError",
]
