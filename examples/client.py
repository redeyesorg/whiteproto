import asyncio
import logging
import os
import time

import coloredlogs  # type: ignore

import whiteproto
from whiteproto._proto import BUFFER_SIZE

PRESHARED_KEY = b"secret"
HOST = "localhost"
PORT = 4414

coloredlogs.install(level="DEBUG")  # type: ignore


async def main():
    connection = await whiteproto.open_connection(HOST, PORT, PRESHARED_KEY)
    connection.set_compression_mode(whiteproto.CompressionMode.ENABLED)
    start_time = time.time()
    await connection.write(os.urandom(1024 * 1024))
    data = await connection.read()
    logging.info(
        "Buffer size %d kB. Operation took: %.2f seconds. Speed is: %.2f MB/s",
        BUFFER_SIZE / 1024,
        time.time() - start_time,
        len(data) / (time.time() - start_time) / 1024 / 1024 * 2,
    )
    await connection.close()


asyncio.run(main())
