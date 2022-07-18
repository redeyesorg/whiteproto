"""WhiteProto client"""
import asyncio

from whiteproto.connection import WhiteConnection, WhitePeerType


async def open_connection(
    host: str, port: int, preshared_key: bytes
) -> WhiteConnection:
    """Opens connection to WhiteProto server

    Args:
        host: Server host
        port: Server port
        preshared_key: Preshared key

    Returns:
        WhiteConnection

    Raises:
        RuntimeError: Initialization failed
    """
    reader, writer = await asyncio.open_connection(host, port)
    connection = WhiteConnection(reader, writer, WhitePeerType.CLIENT)
    if not await connection.initialize(preshared_key):
        raise RuntimeError("Failed to initialize connection")
    return connection
