"""WhiteProto compiled wrapper"""

from typing import Tuple

from whiteproto._proto.parser import HEADER_SIZE, detect_packet, make_header
from whiteproto._proto.wrapper import (
    AnyMessage,
    AnyMessageType,
    ChunkedData,
    ClientChallengeResponse,
    ClientHello,
    CloseConnection,
    CloseConnectionReason,
    ControlMessage,
    ControlMessageType,
    EncryptedMessage,
    ServerHello,
    UpgradeProtocolAck,
    UpgradeProtocolAsk,
    UpgradeProtocolResult,
)

MIN_VERSION = 0x01
CURRENT_VERSION = 0x02
MAX_VERSION = 0x02

BUFFER_SIZE = 2**17  # 128KiB

RESTRICTED_VERSIONS: Tuple[int] = (0,)


__all__ = [
    "ClientHello",
    "ServerHello",
    "UpgradeProtocolAsk",
    "UpgradeProtocolAck",
    "ClientChallengeResponse",
    "CloseConnection",
    "EncryptedMessage",
    "CloseConnectionReason",
    "UpgradeProtocolResult",
    "ChunkedData",
    "ControlMessage",
    "AnyMessage",
    "ControlMessageType",
    "AnyMessageType",
    "detect_packet",
    "make_header",
    "HEADER_SIZE",
    "MIN_VERSION",
    "CURRENT_VERSION",
    "MAX_VERSION",
    "RESTRICTED_VERSIONS",
]
