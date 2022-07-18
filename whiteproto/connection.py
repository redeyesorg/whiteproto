"""WhiteProto connection implementation"""
import enum
import logging
import asyncio

# from typing import Awaitable, Callable

from whiteproto._proto import (
    HEADER_SIZE,
    # MAX_VERSION,
    MIN_VERSION,
    # RESTRICTED_VERSIONS,
    detect_packet,
    make_header,
    AnyMessage,
    CloseConnection,
    CloseConnectionReason,
    # UpgradeProtocolResult,
    # UpgradeProtocolAsk,
    # UpgradeProtocolAck,
)
from whiteproto._proto.wrapper import (
    ClientChallengeResponse,
    ClientHello,
    EncryptedMessage,
    ServerHello,
)
from whiteproto.crypto import Origin, WhiteCryptoContext


logger = logging.getLogger(__name__)


class WhiteConnectionState(enum.Enum):
    """State of the connection"""

    INITIAL = 0
    HANDSHAKE = 2
    ENCRYPTED = 3
    CLOSED = 4


class WhitePeerType(enum.Enum):
    """Type of the peer"""

    CLIENT = 1
    SERVER = 2


class WhiteConnection:
    """WhiteProto connection"""

    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter
    _state: WhiteConnectionState
    _context: WhiteCryptoContext
    _peer_type: WhitePeerType
    _seq: int = 0

    version: int = MIN_VERSION

    def __init__(
        self: "WhiteConnection",
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_type: WhitePeerType = WhitePeerType.CLIENT,
    ):
        self._reader = reader
        self._writer = writer
        self._peer_type = peer_type
        self._state = WhiteConnectionState.INITIAL
        self._context = WhiteCryptoContext()

    async def _wait_next_message(self: "WhiteConnection") -> AnyMessage:
        """Wait for the next message from the server."""

        while self._state != WhiteConnectionState.CLOSED:
            header = await self._reader.read(HEADER_SIZE)
            if len(header) != HEADER_SIZE:
                self._state = WhiteConnectionState.CLOSED
                raise RuntimeError("Connection closed")
            message_type, message_length = detect_packet(header)
            if message_type is None:
                continue
            data = await self._reader.read(message_length)
            if len(data) != message_length:
                self._state = WhiteConnectionState.CLOSED
                raise RuntimeError("Connection closed")
            message = message_type.from_bytes(data)
            if message.version != self.version:
                continue
            return message

        raise RuntimeError("Connection closed")

    def _send(self: "WhiteConnection", message: AnyMessage) -> None:
        if self._state == WhiteConnectionState.CLOSED:
            raise RuntimeError("Connection closed")

        header = make_header(message)
        data = message.serialize()

        self._writer.write(header)
        self._writer.write(data)

    async def _close(self: "WhiteConnection", reason: CloseConnectionReason) -> None:
        self._send(CloseConnection.from_attrs(version=self.version, reason=reason))
        self._state = WhiteConnectionState.CLOSED
        self._writer.close()
        self._reader.feed_eof()
        await self._writer.wait_closed()

    async def _initialize_as_server(  # pylint: disable=too-many-return-statements
        self: "WhiteConnection", preshared_key: bytes
    ) -> bool:
        self._context.set_preshared_key(preshared_key)
        logger.debug("Waiting for client hello")
        client_hello = await self._wait_next_message()
        if not isinstance(client_hello, ClientHello):
            logger.error("Expected client hello, got %s", client_hello)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        self._context.set_remote_public_key(client_hello.pubkey)
        logger.debug("Got client hello, sending server hello")
        self._send(
            ServerHello.from_attrs(
                version=self.version,
                pubkey=self._context.get_public_bytes(),
                nonce=self._context.get_session_nonce(),
            )
        )
        logger.debug("Waiting for client challenge response")
        response = await self._wait_next_message()
        if not isinstance(response, ClientChallengeResponse):
            logger.error("Expected client challenge response, got %s", response)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        if response.nonce != self._context.get_session_nonce():
            logger.error("Client challenge response nonce mismatch")
            await self._close(CloseConnectionReason.ENCRYPTION_ERROR)
            return False
        if response.hash != self._context.calculate_challenge_response():
            logger.error("Client challenge response hash mismatch")
            await self._close(CloseConnectionReason.ENCRYPTION_ERROR)
            return False
        if not self._context.verify(response.hash, response.sig, Origin.REMOTE):
            logger.error("Client challenge response signature mismatch")
            await self._close(CloseConnectionReason.ENCRYPTION_ERROR)
            return False
        logger.debug(
            "Client challenge response verified. Trying to send encrypted message"
        )

        self._seq += 1
        nonce, ciphertext = self._context.encrypt(b"ping", self._seq)
        self._send(
            EncryptedMessage.from_attrs(
                version=self.version,
                seq=self._seq,
                nonce=nonce,
                ciphertext=ciphertext,
            )
        )

        client_encrypted = await self._wait_next_message()
        if not isinstance(client_encrypted, EncryptedMessage):
            logger.error("Expected encrypted message, got %s", client_encrypted)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        if client_encrypted.seq != 2:
            logger.error("Expected encrypted message seq 2, got %s", client_encrypted)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        self._seq += 1

        data = self._context.decrypt(
            client_encrypted.nonce, client_encrypted.ciphertext, self._seq
        )
        if data != b"pong":
            logger.error("Expected encrypted message data pong, got %s", data)
            await self._close(CloseConnectionReason.ENCRYPTION_ERROR)
            return False
        logger.debug("Handshake completed. Connection is now encrypted")
        self._state = WhiteConnectionState.ENCRYPTED
        return True

    async def _initialize_as_client(
        self: "WhiteConnection", preshared_key: bytes
    ) -> bool:
        self._context.set_preshared_key(preshared_key)
        logger.debug("Sending client hello")
        self._send(
            ClientHello.from_attrs(
                version=self.version, pubkey=self._context.get_public_bytes()
            )
        )
        logger.debug("Waiting for server hello")
        server_hello = await self._wait_next_message()
        if not isinstance(server_hello, ServerHello):
            logger.error("Expected server hello, got %s", server_hello)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        self._context.set_session_nonce(server_hello.nonce)
        self._context.set_remote_public_key(server_hello.pubkey)
        response = self._context.calculate_challenge_response()
        response_sig = self._context.sign(response)
        logger.debug("Got server hello, sending client challenge response")
        self._send(
            ClientChallengeResponse.from_attrs(
                version=self.version,
                nonce=self._context.get_session_nonce(),
                sig=response_sig,
                hash=response,
            )
        )
        logger.debug("Waiting for encrypted message")
        server_encrypted = await self._wait_next_message()
        if isinstance(server_encrypted, CloseConnection):
            logger.error("Server closed connection: %s", server_encrypted.reason)
            self._state = WhiteConnectionState.CLOSED
            return False
        if not isinstance(server_encrypted, EncryptedMessage):
            logger.error("Expected encrypted message, got %s", server_encrypted)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        if server_encrypted.seq != 1:
            logger.error("Expected encrypted message seq 1, got %s", server_encrypted)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        self._seq += 1
        data = self._context.decrypt(
            server_encrypted.nonce, server_encrypted.ciphertext, self._seq
        )
        if data != b"ping":
            logger.error("Expected encrypted message data ping, got %s", data)
            await self._close(CloseConnectionReason.ENCRYPTION_ERROR)
            return False
        logger.debug("Got server's encrypted message, sending my encrypted message")
        self._seq += 1
        nonce, ciphertext = self._context.encrypt(b"pong", self._seq)
        self._send(
            EncryptedMessage.from_attrs(
                version=self.version,
                seq=self._seq,
                nonce=nonce,
                ciphertext=ciphertext,
            )
        )
        logger.debug("Handshake completed. Connection is now encrypted")
        self._state = WhiteConnectionState.ENCRYPTED
        return True

    async def initialize(self: "WhiteConnection", preshared_key: bytes) -> bool:
        """Initializes whiteproto connection

        This method must be called before any other method.

        Args:
            preshared_key: Preshared key to use for authentication.

        Returns:
            True if handshake was successful, False otherwise.
        """
        if self._state == WhiteConnectionState.CLOSED:
            logger.error("Connection is closed")
            return False
        if self._state == WhiteConnectionState.ENCRYPTED:
            logger.error("Connection is already encrypted")
            return False
        self._state = WhiteConnectionState.HANDSHAKE
        if self._peer_type == WhitePeerType.CLIENT:
            return await self._initialize_as_client(preshared_key)
        if self._peer_type == WhitePeerType.SERVER:
            return await self._initialize_as_server(preshared_key)
        raise ValueError("Unknown peer type")

    def write(self: "WhiteConnection", data: bytes) -> None:
        """Writes data to the connection.

        Method should be used along with the `drain()` method.

        Args:
            data: Data to write.
        """
        self._seq += 1
        nonce, ciphertext = self._context.encrypt(data, self._seq)
        self._send(
            EncryptedMessage.from_attrs(
                version=self.version,
                seq=self._seq,
                nonce=nonce,
                ciphertext=ciphertext,
            )
        )

    async def read(self: "WhiteConnection") -> bytes:
        """Reads data from the connection.

        Returns:
            Data read.
        """
        if self._state != WhiteConnectionState.ENCRYPTED:
            raise RuntimeError("Connection is in invalid state")
        encrypted = await self._wait_next_message()
        if isinstance(encrypted, CloseConnection):
            logger.error("Connection closed: %s", encrypted.reason)
            self._state = WhiteConnectionState.CLOSED
            return b""
        if not isinstance(encrypted, EncryptedMessage):
            logger.error("Expected encrypted message, got %s", encrypted)
            return b""
        self._seq += 1
        data = self._context.decrypt(encrypted.nonce, encrypted.ciphertext, self._seq)
        return data

    async def drain(self: "WhiteConnection") -> None:
        """Waits for all data to be writed.

        See StreamWriter.drain() for more information.
        """
        await self._writer.drain()

    async def close(self: "WhiteConnection", reason: CloseConnectionReason = CloseConnectionReason.OK) -> None:
        """Closes the connection.

        Args:
            reason: Reason for closing the connection.
        """
        await self._close(reason)
