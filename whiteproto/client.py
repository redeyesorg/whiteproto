"""WhiteProto client."""
import asyncio

from whiteproto.connection import FragmentationMode, WhiteConnection, PeerType
from whiteproto._proto import BUFFER_SIZE


async def open_connection(
    host: str,
    port: int,
    preshared_key: bytes,
    fragmentation_mode: FragmentationMode = FragmentationMode.OPTIONAL,
) -> WhiteConnection:
    """Opens connection to WhiteProto server.

    Args:
        host: Server host
        port: Server port
        preshared_key: Preshared key

    Returns:
        WhiteConnection

    Raises:
        RuntimeError: Initialization failed
    """
    reader, writer = await asyncio.open_connection(host, port, limit=BUFFER_SIZE)
    connection = WhiteConnection(reader, writer, PeerType.CLIENT)
    connection.set_fragmentation_mode(fragmentation_mode)
    if not await connection.initialize(preshared_key):
        raise RuntimeError("Failed to initialize connection")
    return connection
