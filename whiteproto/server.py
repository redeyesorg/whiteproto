"""WhiteProto server implementation."""

import asyncio
import logging
from typing import Awaitable, Callable

from whiteproto._proto import BUFFER_SIZE, CloseConnectionReason
from whiteproto.connection import PeerType, WhiteConnection

logger = logging.getLogger(__name__)


async def _fallback_handler(connection: WhiteConnection) -> None:
    # close all connections if no callback set
    logger.error("No callback set, closing connection")
    await connection.close(CloseConnectionReason.OK)


class WhiteServer:  # noqa: WPS306
    """WhiteProto server"""

    _server: asyncio.AbstractServer
    _on_connection: Callable[[WhiteConnection], Awaitable[None]]

    def __init__(
        self: "WhiteServer", host: str, port: int, preshared_key: bytes
    ) -> None:
        self.host = host
        self.port = port
        self.loop = asyncio.get_event_loop()
        self.preshared_key = preshared_key
        self._on_connection = _fallback_handler

    def set_callback(
        self: "WhiteServer", callback: Callable[[WhiteConnection], Awaitable[None]]
    ) -> None:
        """Sets callback for new connections

        Args:
            callback: Callback
        """
        self._on_connection = callback

    async def start(self: "WhiteServer") -> None:
        """Starts server"""
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port, limit=BUFFER_SIZE
        )
        logger.info("Server started on %s:%d", self.host, self.port)

    async def serve_forever(self: "WhiteServer") -> None:
        """Serves connections forever

        Raises:
            RuntimeError: Server not started
        """
        if not self._server:
            raise RuntimeError("Server not started")
        await self._server.serve_forever()

    async def _handle_client(
        self: "WhiteServer", reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        connection = WhiteConnection(reader, writer, PeerType.SERVER)
        if not await connection.initialize(self.preshared_key):
            logger.error("Failed to initialize connection")
            return
        logger.info("Initialized!")
        await self._on_connection(connection)
