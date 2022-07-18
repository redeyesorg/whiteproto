import asyncio
import logging
import coloredlogs  # type: ignore
import whiteproto

PRESHARED_KEY = b"secret"
HOST = "localhost"
PORT = 4414

coloredlogs.install(level="DEBUG")  # type: ignore


async def main():
    connection = await whiteproto.open_connection(HOST, PORT, PRESHARED_KEY)
    while True:
        connection.write(b"Hello!" * 10000)
        await connection.drain()
        data = await connection.read()
        if not data:
            break
        logging.info("Received: %d", len(data))
        await asyncio.sleep(1)


asyncio.run(main())
