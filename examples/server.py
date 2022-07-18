import asyncio
import logging
import coloredlogs  # type: ignore
import whiteproto

PRESHARED_KEY = b"secret"
HOST = "localhost"
PORT = 4414

coloredlogs.install(level="DEBUG")  # type: ignore


async def on_connection(connection: whiteproto.WhiteConnection):
    while True:
        data = await connection.read()
        if not data:
            break
        logging.info("Received: %d", len(data))
        connection.write(data)
        await connection.drain()


async def main():
    server = whiteproto.WhiteServer(HOST, PORT, PRESHARED_KEY)
    server.set_callback(on_connection)
    await server.start()
    await server.serve_forever()


asyncio.run(main())
