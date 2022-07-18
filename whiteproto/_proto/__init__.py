"""WhiteProto compiled wrapper"""

from typing import Tuple
from whiteproto._proto.wrapper import (
    ClientHello,
    ServerHello,
    UpgradeProtocolAsk,
    UpgradeProtocolAck,
    ClientChallengeResponse,
    CloseConnection,
    EncryptedMessage,
    CloseConnectionReason,
    UpgradeProtocolResult,
    ControlMessage,
    AnyMessage,
    ControlMessageType,
    AnyMessageType,
)
from whiteproto._proto.parser import detect_packet, make_header, HEADER_SIZE

MIN_VERSION = 0x01
CURRENT_VERSION = 0x01
MAX_VERSION = 0x01

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
