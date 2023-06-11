"""Parser for whiteproto"""

import struct

from whiteproto._proto.wrapper import (
    AnyMessage,
    AnyMessageType,
    ChunkedData,
    ClientChallengeResponse,
    ClientHello,
    CloseConnection,
    EncryptedMessage,
    ServerHello,
    UpgradeProtocolAck,
    UpgradeProtocolAsk,
)

_DESCRIPTOR_MAP = {
    0x00: None,
    0x01: ClientHello,
    0x02: ServerHello,
    0x03: UpgradeProtocolAsk,
    0x04: UpgradeProtocolAck,
    0x05: ClientChallengeResponse,
    0x06: CloseConnection,
    0x07: ChunkedData,
    0xA1: EncryptedMessage,
}

_DESCRIPTOR_MAP_REV = {v: k for k, v in _DESCRIPTOR_MAP.items()}

HEADER_SIZE = struct.calcsize("!BI")


def detect_packet(data: bytes) -> tuple[AnyMessageType | None, int]:
    """Detect the packet type of the given data"""
    descriptor, length = struct.unpack("!BI", data[:HEADER_SIZE])
    return _DESCRIPTOR_MAP.get(descriptor, None), length


def make_header(message: AnyMessage) -> bytes:
    """Make a header for the given message"""
    return struct.pack(
        "!BI", _DESCRIPTOR_MAP_REV[type(message)], len(message.serialize())
    )
