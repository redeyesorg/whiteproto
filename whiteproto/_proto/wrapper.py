# pylint: disable=no-member

"""Wrapper for protobuf compiled whiteproto description"""

import abc
import enum
from typing import Any, Callable, Type, TypeVar

from google.protobuf.pyext.cpp_message import (
    GeneratedProtocolMessageType,  # type: ignore
)

try:
    from whiteproto._proto._compiled.org.redeyes import (
        secure_pb2 as _compiled,  # type: ignore
    )
except ImportError:
    raise ImportError(
        "Failed to import compiled protocol. Are you forgot to run `ninja -v protos`?"
    ) from None

sentinel = object()
T = TypeVar("T", bound="_BaseMessage")


class _UpgradeProtocolResult(enum.Enum):
    OK = _compiled.UpgradeProtocolAck.UpgradeProtocolResult.OK  # type: ignore
    ERROR = _compiled.UpgradeProtocolAck.UpgradeProtocolResult.ERROR  # type: ignore


class _CloseConnectionReason(enum.Enum):
    UNKNOWN = _compiled.CloseConnection.CloseConnectionReason.UNKNOWN  # type: ignore
    PROTOCOL_ERROR = _compiled.CloseConnection.CloseConnectionReason.PROTOCOL_ERROR  # type: ignore
    HANDSHAKE_FAILED = _compiled.CloseConnection.CloseConnectionReason.HANDSHAKE_FAILED  # type: ignore
    ENCRYPTION_ERROR = _compiled.CloseConnection.CloseConnectionReason.ENCRYPTION_ERROR  # type: ignore
    TIMEOUT = _compiled.CloseConnection.CloseConnectionReason.TIMEOUT  # type: ignore
    AGAIN = _compiled.CloseConnection.CloseConnectionReason.AGAIN  # type: ignore
    OK = _compiled.CloseConnection.CloseConnectionReason.OK  # type: ignore


class _BaseMessage(abc.ABC):
    _wraps_instance: GeneratedProtocolMessageType | None = None
    _fields: list[str]
    _attr_convertors: dict[str, Callable[[Any], Any]] | None = None
    _rev_attr_convertors: dict[str, Callable[[Any], Any]] | None = None
    _available_from_version = 0

    def __init__(self: "_BaseMessage"):
        self._fields = [field.name for field in self._wraps.DESCRIPTOR.fields]  # type: ignore
        if not self._attr_convertors:
            self._attr_convertors = {}
        if not self._rev_attr_convertors:
            self._rev_attr_convertors = {}

    @property
    @abc.abstractmethod
    def _wraps(self: "_BaseMessage") -> Type[GeneratedProtocolMessageType]:
        ...

    def __repr__(self: "_BaseMessage") -> str:
        if not self._wraps_instance:
            return f"<{self.__class__.__name__} uninitialized>"
        attrs = [name + "=" + repr(getattr(self, name)) for name in self._fields]
        return f"<{self.__class__.__name__} {' '.join(attrs)}>"

    def __getattr__(self: "_BaseMessage", __name: str) -> Any:
        if not self._wraps_instance:  # type: ignore
            raise RuntimeError(
                "Trying to use uninitialized message "
                f"{self._wraps.DESCRIPTOR.full_name!r}"  # type: ignore
            )
        if __name not in self._fields:
            raise AttributeError(__name)
        attr = getattr(self._wraps_instance, __name, sentinel)  # type: ignore
        if attr is sentinel:
            raise RuntimeError(
                "Trying to use partially initialized message "
                f"{self._wraps.DESCRIPTOR.full_name!r}"  # type: ignore
            )
        assert self._rev_attr_convertors is not None
        return self._rev_attr_convertors.get(__name, lambda x: x)(attr)

    def __setattribute__(self: "_BaseMessage", __name: str, __value: Any) -> None:
        del __name, __value
        raise NotImplementedError("Cannot set attributes on messages")

    @classmethod
    def from_bytes(cls: Type[T], string: bytes) -> T:
        """Create a message from a serialized byte string."""
        message = cls()
        message._wraps_instance = message._wraps()
        message._wraps_instance.ParseFromString(string)  # type: ignore
        return message

    @classmethod
    def from_attrs(cls: Type[T], *, version: int, **kwargs: Any) -> T:
        """Create a message from a set of attributes."""
        if version < cls._available_from_version:
            raise ValueError(
                f"Message {cls.__name__} is not available in version {version}"
            )
        message = cls()
        assert message._attr_convertors is not None
        for name, convertor in message._attr_convertors.items():
            if name in kwargs:
                kwargs[name] = convertor(kwargs[name])
        message._wraps_instance = message._wraps(version=version, **kwargs)
        return message

    def serialize(self: "_BaseMessage") -> bytes:
        """Serialize the message to a byte string."""
        if not self._wraps_instance:  # type: ignore
            raise RuntimeError(
                "Trying to serialize uninitialized message "
                f"{self._wraps.DESCRIPTOR.full_name!r}"  # type: ignore
            )
        return self._wraps_instance.SerializeToString()  # type: ignore

    version: int


class ClientHello(_BaseMessage):
    """Wrapper for ClientHello message"""

    _wraps = _compiled.ClientHello  # type: ignore
    _available_from_version = 1

    pubkey: bytes


class ServerHello(_BaseMessage):
    """Wrapper for ServerHello message"""

    _wraps = _compiled.ServerHello  # type: ignore
    _available_from_version = 1

    pubkey: bytes
    nonce: bytes


class UpgradeProtocolAsk(_BaseMessage):
    """Wrapper for UpgradeProtocolAsk message"""

    _wraps = _compiled.UpgradeProtocolAsk  # type: ignore
    _available_from_version = 1

    new_version: int


class UpgradeProtocolAck(_BaseMessage):
    """Wrapper for UpgradeProtocolAck message"""

    _wraps = _compiled.UpgradeProtocolAck  # type: ignore
    _available_from_version = 1

    _attr_convertors = {
        "result": lambda x: _UpgradeProtocolResult(x).value,
    }
    _rev_attr_convertors = {
        "result": _UpgradeProtocolResult,
    }

    result: _UpgradeProtocolResult


class ClientChallengeResponse(_BaseMessage):
    """Wrapper for ClientChallengeResponse message"""

    _wraps = _compiled.ClientChallengeResponse  # type: ignore
    _available_from_version = 1

    nonce: bytes
    sig: bytes
    hash: bytes  # noqa: A003


class CloseConnection(_BaseMessage):
    """Wrapper for HandshakeFailure message"""

    _wraps = _compiled.CloseConnection  # type: ignore
    _available_from_version = 1

    _attr_convertors = {
        "reason": lambda x: _CloseConnectionReason(x).value,
    }
    _rev_attr_convertors = {
        "reason": _CloseConnectionReason,
    }

    reason: _CloseConnectionReason


class EncryptedMessage(_BaseMessage):
    """Wrapper for EncryptedMessage message"""

    _wraps = _compiled.EncryptedMessage  # type: ignore
    _available_from_version = 1

    seq: int
    nonce: bytes
    ciphertext: bytes


class ChunkedData(_BaseMessage):
    """Wrapper for ChunkedData message"""

    _wraps = _compiled.ChunkedData  # type: ignore
    _available_from_version = 2

    seq: int
    count: int
    nonce: bytes
    compressed: bool


CloseConnectionReason = _CloseConnectionReason
UpgradeProtocolResult = _UpgradeProtocolResult

ControlMessage = (
    ClientHello
    | ServerHello
    | UpgradeProtocolAsk
    | UpgradeProtocolAck
    | ClientChallengeResponse
    | CloseConnection
    | ChunkedData
)
AnyMessage = ControlMessage | EncryptedMessage

ControlMessageType = (
    Type[ClientHello]
    | Type[ServerHello]
    | Type[UpgradeProtocolAsk]
    | Type[UpgradeProtocolAck]
    | Type[ClientChallengeResponse]
    | Type[CloseConnection]
    | Type[ChunkedData]
)

AnyMessageType = ControlMessageType | Type[EncryptedMessage]
