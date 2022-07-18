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
    for i in range(10):
        connection.write(b"Hello %d" % i)
        await connection.drain()
        data = await connection.read()
        logging.info("Received reply: %s", data)
    await connection.close()


asyncio.run(main())
