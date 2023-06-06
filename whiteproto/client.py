"""WhiteProto client."""
import asyncio

from whiteproto._proto import BUFFER_SIZE
from whiteproto.connection import FragmentationMode, PeerType, WhiteConnection


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
        fragmentation_mode: Fragmentation mode

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
