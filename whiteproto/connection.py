"""WhiteProto connection implementation."""
import asyncio
import enum
import logging
import math

from whiteproto._proto import (
    BUFFER_SIZE,
    CURRENT_VERSION,
    HEADER_SIZE,
    MAX_VERSION,
    MIN_VERSION,
    RESTRICTED_VERSIONS,
    AnyMessage,
    ChunkedData,
    ClientChallengeResponse,
    ClientHello,
    CloseConnection,
    CloseConnectionReason,
    EncryptedMessage,
    ServerHello,
    UpgradeProtocolAck,
    UpgradeProtocolAsk,
    UpgradeProtocolResult,
    detect_packet,
    make_header,
)
from whiteproto.compression import CompressionMode, compress, decompress
from whiteproto.crypto import CryptoContext, Origin

logger = logging.getLogger(__name__)

MAX_DATA_SIZE = BUFFER_SIZE - 4096  # Leave 4096 bytes for protocol needs

EXPECTED_ENCRYPTED_MESSAGE_ERROR = "Expected encrypted message, got %s"


class ConnectionState(enum.Enum):
    """State of the connection"""

    INITIAL = 1
    HANDSHAKE = 2
    ENCRYPTED = 3
    CLOSED = 4


class PeerType(enum.Enum):
    """Type of the peer"""

    CLIENT = 1
    SERVER = 2


class FragmentationMode(enum.Enum):
    """Fragmentation mode of the connection.

    Fragmentation mode helps to determine whether the protocol
    version should be upgraded and to require the possibility
    of data fragmentation. Fragmentation mode is applicable
    only to the client.

    NOT_REQUIRED - Fragmentation is not required.
    OPTIONAL - Fragmentation will be enabled if possible.
    REQUIRED - Fragmentation is required. If the protocol cannot
    be upgraded to the required version, an exception will be
    thrown.
    """

    NOT_REQUIRED = 1
    OPTIONAL = 2
    REQUIRED = 3


class ConnectionClosedError(Exception):
    """Connection closed"""

    reason: CloseConnectionReason | None = None

    def __init__(
        self: "ConnectionClosedError", reason: CloseConnectionReason | None = None
    ):
        if reason is None:
            message = "Connection closed"
        else:
            message = f"Connection closed with code {reason.value} ({reason.name})"
        self.reason = reason
        super().__init__(message)


class WhiteConnection:  # noqa: WPS306
    """WhiteProto connection"""

    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter
    _state: ConnectionState
    _context: CryptoContext
    _peer_type: PeerType
    _transmission_lock: asyncio.Lock
    _fragmentation_mode: FragmentationMode = FragmentationMode.NOT_REQUIRED
    _compression_mode: CompressionMode = CompressionMode.DISABLED
    _seq: int = 0

    version: int = MIN_VERSION

    def __init__(
        self: "WhiteConnection",
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_type: PeerType = PeerType.CLIENT,
    ):
        self._reader = reader
        self._writer = writer
        self._peer_type = peer_type
        self._state = ConnectionState.INITIAL
        self._context = CryptoContext()
        self._transmission_lock = asyncio.Lock()
        self._loop = asyncio.get_event_loop()

    async def initialize(self: "WhiteConnection", preshared_key: bytes) -> bool:
        """Initializes whiteproto connection

        This method must be called before any other method.

        Args:
            preshared_key: Preshared key to use for authentication.

        Returns:
            True if handshake was successful, False otherwise.

        Raises:
            ValueError: If connection is already initialized.
        """
        if self._state == ConnectionState.CLOSED:
            logger.error("Connection is closed")
            return False
        if self._state == ConnectionState.ENCRYPTED:
            logger.error("Connection is already encrypted")
            return False
        async with self._transmission_lock:
            self._state = ConnectionState.HANDSHAKE
            if self._peer_type == PeerType.CLIENT:
                return await self._initialize_as_client(preshared_key)
            if self._peer_type == PeerType.SERVER:
                return await self._initialize_as_server(preshared_key)
        raise ValueError("Unknown peer type")

    def set_fragmentation_mode(
        self: "WhiteConnection", mode: FragmentationMode
    ) -> None:
        """Sets fragmentation mode for this connection.

        Args:
            mode: Fragmentation mode to use.

        Raises:
            ValueError: If fragmentation mode is not supported.
        """
        if CURRENT_VERSION < 2:
            raise ValueError("Fragmentation is not supported in this version")
        if self._peer_type == PeerType.SERVER:
            raise ValueError("Fragmentation can only be set by client")
        self._fragmentation_mode = mode

    def set_compression_mode(self: "WhiteConnection", mode: CompressionMode) -> None:
        """Sets compression mode for this connection.

        Args:
            mode: Compression mode to use.

        Raises:
            ValueError: If compression mode is not supported.
        """
        if CURRENT_VERSION < 2:
            raise ValueError("Compression is not supported in this version")
        self._compression_mode = mode

    async def write(self: "WhiteConnection", data: bytes) -> None:
        """Writes data to the connection.

        Args:
            data: Data to write.

        Raises:
            RuntimeError: If connection is in invalid state.
            ValueError: If data is too large for this connection.
        """
        if self._state != ConnectionState.ENCRYPTED:
            raise RuntimeError("Connection is in invalid state")

        data_len = len(data)

        if data_len < MAX_DATA_SIZE:
            self._seq += 1
            logger.debug("Encrypting %d bytes", data_len)
            nonce, ciphertext = await self._context.encrypt(data, self._seq)
            await self._send(
                EncryptedMessage.from_attrs(
                    version=self.version,
                    seq=self._seq,
                    nonce=nonce,
                    ciphertext=ciphertext,
                )
            )
            return
        if self._fragmentation_mode == FragmentationMode.NOT_REQUIRED:
            raise ValueError(
                "Data is too large for this connection, enable fragmentation"
            )
        if self.version < 2:  # Fragmentation available from version 2
            raise ValueError(
                "Data is too large and fragmentation mode is not supported in this version"
            )
        async with self._transmission_lock:
            self._seq += 1
            compressed = False
            if self._compression_mode == CompressionMode.ENABLED:
                logger.debug("Compressing %d bytes", data_len)
                compressed_data = await compress(data)
                if len(compressed_data) < data_len:
                    compressed = True
                    data = compressed_data
            logger.debug("Encrypting %d bytes", len(data))
            nonce, ciphertext = await self._context.encrypt(data, self._seq)
            chunks_count = math.ceil(len(ciphertext) / MAX_DATA_SIZE)
            logger.debug("Sending %d chunks", chunks_count)
            await self._send(
                ChunkedData.from_attrs(
                    version=self.version,
                    seq=self._seq,
                    count=chunks_count,
                    nonce=nonce,
                    compressed=compressed,
                )
            )
            for idx in range(chunks_count):
                await self._send(
                    EncryptedMessage.from_attrs(
                        version=self.version,
                        seq=self._seq,
                        nonce=b"CHUNKED",
                        ciphertext=ciphertext[
                            idx
                            * MAX_DATA_SIZE : (idx + 1)  # noqa: E203
                            * MAX_DATA_SIZE
                        ],
                    )
                )

    async def read(self: "WhiteConnection") -> bytes:  # noqa: WPS231
        """Reads data from the connection.

        Returns:
            Data read.

        Raises:
            RuntimeError: If connection is in invalid state.
            ConnectionClosedError: If connection is closed.
        """
        if self._state != ConnectionState.ENCRYPTED:
            raise RuntimeError("Connection is in invalid state")

        message = await self._wait_next_message()
        if isinstance(message, ChunkedData):
            if message.compressed:
                logger.debug("Fragmented+compressed data received")
            else:
                logger.debug("Fragmented data received")
            self._seq += 1
            if self._seq != message.seq:
                logger.error("Expected seq %d, got %d", self._seq, message.seq)
                await self._close(CloseConnectionReason.PROTOCOL_ERROR)
                raise ConnectionClosedError()
            buffer = b""
            for _ in range(message.count):
                chunk = await self._wait_next_message()
                if not isinstance(chunk, EncryptedMessage):
                    logger.error(EXPECTED_ENCRYPTED_MESSAGE_ERROR, chunk)
                    await self._close(CloseConnectionReason.PROTOCOL_ERROR)
                    raise ConnectionClosedError()
                if chunk.nonce != b"CHUNKED":
                    logger.error(
                        "Expected encrypted message nonce CHUNKED, got %s", chunk
                    )
                    await self._close(CloseConnectionReason.PROTOCOL_ERROR)
                    raise ConnectionClosedError()
                buffer += chunk.ciphertext
            logger.debug("Decrypting")
            data = await self._context.decrypt(message.nonce, buffer, message.seq)
            if message.compressed:
                logger.debug("Decompressing")
                data = await decompress(data)
            return data
        if isinstance(message, EncryptedMessage):
            self._seq += 1
            if self._seq != message.seq:
                logger.error(
                    "Expected encrypted message seq %d, got %d", self._seq, message.seq
                )
                await self._close(CloseConnectionReason.PROTOCOL_ERROR)
                raise ConnectionClosedError()
            return await self._context.decrypt(
                message.nonce, message.ciphertext, message.seq
            )
        if isinstance(message, CloseConnection):
            self._state = ConnectionState.CLOSED
            raise ConnectionClosedError(message.reason)
        logger.error(EXPECTED_ENCRYPTED_MESSAGE_ERROR, message)
        await self._close(CloseConnectionReason.PROTOCOL_ERROR)
        raise ConnectionClosedError()

    async def close(
        self: "WhiteConnection",
        reason: CloseConnectionReason = CloseConnectionReason.OK,
    ) -> None:
        """Closes the connection.

        Args:
            reason: Reason for closing the connection.
        """
        await self._close(reason)

    async def _wait_next_message(self: "WhiteConnection") -> AnyMessage:
        """Wait for the next message from the server.

        Returns:
            Next message from the server.

        Raises:
            ConnectionClosedError: If connection is closed.
        """
        while self._state != ConnectionState.CLOSED:
            try:
                header = await self._reader.readexactly(HEADER_SIZE)
            except asyncio.IncompleteReadError as err:
                logger.error(
                    "Received header %s with len %d, required len is %d",
                    err.partial,
                    len(err.partial),
                    HEADER_SIZE,
                )
                self._state = ConnectionState.CLOSED
                raise ConnectionClosedError() from None
            message_type, message_length = detect_packet(header)
            if message_type is None:
                await self._reader.readexactly(message_length)
                logger.debug("Received unknown message type")
                continue
            try:
                data = await self._reader.readexactly(message_length)
            except asyncio.IncompleteReadError as err:  # noqa: WPS440
                logger.error(
                    "Received message with len %d, required len is %d",
                    len(err.partial),
                    message_length,
                )
                self._state = ConnectionState.CLOSED
                raise ConnectionClosedError() from None
            message = message_type.from_bytes(data)
            if message.version > self.version:
                continue
            return message

        raise ConnectionClosedError()

    def _emergency_read(self: "WhiteConnection") -> AnyMessage | None:
        buffer: bytearray = self._reader._buffer  # type: ignore  # noqa: WPS437
        if not isinstance(buffer, bytearray):
            return None
        while True:
            if len(buffer) < HEADER_SIZE:
                break
            header = bytes(buffer[:HEADER_SIZE])
            del buffer[:HEADER_SIZE]
            message_type, message_length = detect_packet(header)
            if message_type is None:
                if len(buffer) < message_length:
                    break
                del buffer[:message_length]
                continue
            if len(buffer) < message_length:
                break
            data = bytes(buffer[:message_length])
            del buffer[:message_length]
            return message_type.from_bytes(data)
        return None

    async def _send(self: "WhiteConnection", message: AnyMessage) -> None:
        if self._state == ConnectionState.CLOSED:
            raise ConnectionClosedError()

        header = make_header(message)
        data = message.serialize()

        self._writer.write(header)
        self._writer.write(data)

        try:
            await self._writer.drain()
        except ConnectionResetError:
            possible_close = self._emergency_read()
            if possible_close is not None:
                if isinstance(possible_close, CloseConnection):
                    self._state = ConnectionState.CLOSED
                    raise ConnectionClosedError(possible_close.reason) from None
                logger.debug("Whoops. Looks like we broke something")
            raise

    async def _close(self: "WhiteConnection", reason: CloseConnectionReason) -> None:
        await self._send(
            CloseConnection.from_attrs(version=self.version, reason=reason)
        )
        self._state = ConnectionState.CLOSED
        self._writer.close()
        self._reader.feed_eof()
        await self._writer.wait_closed()

    async def _initialize_as_server(  # noqa: WPS217, WPS212, WPS213
        self: "WhiteConnection", preshared_key: bytes
    ) -> bool:
        self._fragmentation_mode = FragmentationMode.OPTIONAL
        self._context.set_preshared_key(preshared_key)
        logger.debug("Waiting for client hello")
        client_hello = await self._wait_next_message()
        if not isinstance(client_hello, ClientHello):
            logger.error("Expected client hello, got %s", client_hello)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        await self._context.set_remote_public_key(client_hello.pubkey)
        logger.debug("Got client hello, sending server hello")
        await self._send(
            ServerHello.from_attrs(
                version=self.version,
                pubkey=self._context.get_public_bytes(),
                nonce=self._context.get_session_nonce(),
            )
        )
        logger.debug("Waiting for client challenge response")
        response = await self._wait_next_message()
        if isinstance(response, UpgradeProtocolAsk):
            logger.debug("Received protocol upgrade request")
            if (  # noqa: WPS337
                response.new_version > MAX_VERSION
                or response.new_version < MIN_VERSION
                or response.new_version in RESTRICTED_VERSIONS
                or response.new_version == self.version
            ):
                logger.debug(
                    "Protocol upgrade failed, requested version: %d",
                    response.new_version,
                )
                await self._send(
                    UpgradeProtocolAck.from_attrs(
                        version=self.version,
                        result=UpgradeProtocolResult.ERROR,
                    )
                )
            else:
                logger.debug("Protocol upgraded to version %d", response.new_version)
                self.version = response.new_version
                await self._send(
                    UpgradeProtocolAck.from_attrs(
                        version=self.version,
                        result=UpgradeProtocolResult.OK,
                    )
                )
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
        if not await self._context.verify(response.hash, response.sig, Origin.REMOTE):
            logger.error("Client challenge response signature mismatch")
            await self._close(CloseConnectionReason.ENCRYPTION_ERROR)
            return False
        logger.debug(
            "Client challenge response verified. Trying to send encrypted message"
        )

        self._seq += 1
        nonce, ciphertext = await self._context.encrypt(b"ping", self._seq)
        await self._send(
            EncryptedMessage.from_attrs(
                version=self.version,
                seq=self._seq,
                nonce=nonce,
                ciphertext=ciphertext,
            )
        )

        client_encrypted = await self._wait_next_message()
        if not isinstance(client_encrypted, EncryptedMessage):
            logger.error(EXPECTED_ENCRYPTED_MESSAGE_ERROR, client_encrypted)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        if client_encrypted.seq != 2:
            logger.error("Expected encrypted message seq 2, got %s", client_encrypted)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        self._seq += 1

        data = await self._context.decrypt(
            client_encrypted.nonce, client_encrypted.ciphertext, self._seq
        )
        if data != b"pong":
            logger.error("Expected encrypted message data pong, got %s", data)
            await self._close(CloseConnectionReason.ENCRYPTION_ERROR)
            return False
        logger.debug("Handshake completed. Connection is now encrypted")
        self._state = ConnectionState.ENCRYPTED
        return True

    async def _initialize_as_client(  # noqa: WPS217, WPS212, WPS213
        self: "WhiteConnection", preshared_key: bytes
    ) -> bool:
        self._context.set_preshared_key(preshared_key)
        logger.debug("Sending client hello")
        await self._send(
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
        await self._context.set_remote_public_key(server_hello.pubkey)
        if CURRENT_VERSION > server_hello.version:
            logger.debug("Newer version available, trying to upgrade")
            await self._send(
                UpgradeProtocolAsk.from_attrs(
                    version=self.version, new_version=CURRENT_VERSION
                )
            )
            self.version = CURRENT_VERSION
            logger.debug("Waiting for upgrade protocol response")
            upgrade_response = await self._wait_next_message()
            if not isinstance(upgrade_response, UpgradeProtocolAck):
                logger.error(
                    "Expected upgrade protocol response, got %s", upgrade_response
                )
                await self._close(CloseConnectionReason.PROTOCOL_ERROR)
                return False
            if upgrade_response.result == UpgradeProtocolResult.OK:
                logger.debug("Protocol upgraded to version %d", self.version)
            elif upgrade_response.result == UpgradeProtocolResult.ERROR:
                self.version = MIN_VERSION
                logger.debug("Protocol upgrade failed")
                if self._fragmentation_mode == FragmentationMode.REQUIRED:
                    logger.error(
                        "Fragmentation mode is required, but server does not support it"
                    )
                    await self._close(CloseConnectionReason.PROTOCOL_ERROR)
                    return False
        response = self._context.calculate_challenge_response()
        response_sig = await self._context.sign(response)
        logger.debug("Got server hello, sending client challenge response")
        await self._send(
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
            self._state = ConnectionState.CLOSED
            return False
        if not isinstance(server_encrypted, EncryptedMessage):
            logger.error(EXPECTED_ENCRYPTED_MESSAGE_ERROR, server_encrypted)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        if server_encrypted.seq != 1:
            logger.error("Expected encrypted message seq 1, got %s", server_encrypted)
            await self._close(CloseConnectionReason.PROTOCOL_ERROR)
            return False
        self._seq += 1
        data = await self._context.decrypt(
            server_encrypted.nonce, server_encrypted.ciphertext, self._seq
        )
        if data != b"ping":
            logger.error("Expected encrypted message data ping, got %s", data)
            await self._close(CloseConnectionReason.ENCRYPTION_ERROR)
            return False
        logger.debug("Got server's encrypted message, sending my encrypted message")
        self._seq += 1
        nonce, ciphertext = await self._context.encrypt(b"pong", self._seq)
        await self._send(
            EncryptedMessage.from_attrs(
                version=self.version,
                seq=self._seq,
                nonce=nonce,
                ciphertext=ciphertext,
            )
        )
        logger.debug("Handshake completed. Connection is now encrypted")
        self._state = ConnectionState.ENCRYPTED
        return True
