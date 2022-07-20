import asyncio
import logging
import coloredlogs  # type: ignore
import whiteproto
from whiteproto.compression import CompressionMode

PRESHARED_KEY = b"secret"
HOST = "localhost"
PORT = 4414

coloredlogs.install(level="DEBUG")  # type: ignore


async def on_connection(connection: whiteproto.WhiteConnection):
    logging.info("New connection")
    connection.set_compression_mode(CompressionMode.ENABLED)
    while True:
        data = await connection.read()
        if not data:
            break
        logging.info("Received message with size %d", len(data))
        await connection.write(data)


async def main():
    server = whiteproto.WhiteServer(HOST, PORT, PRESHARED_KEY)
    server.set_callback(on_connection)
    await server.start()
    await server.serve_forever()


asyncio.run(main())
