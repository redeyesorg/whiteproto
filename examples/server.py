import asyncio
import logging
import coloredlogs  # type: ignore
import whiteproto

PRESHARED_KEY = b"secret"
HOST = "localhost"
PORT = 4414

coloredlogs.install(level="DEBUG")  # type: ignore


async def on_connection(connection: whiteproto.WhiteConnection):
    logging.info("New connection")
    connection.set_compression_mode(whiteproto.CompressionMode.ENABLED)
    while True:
        try:
            data = await connection.read()
        except whiteproto.ConnectionClosed as err:
            if err.reason:
                logging.info(
                    "Connection closed with code %d (%s)",
                    err.reason.value,
                    err.reason.name,
                )
            else:
                logging.info("Connection closed")
            break
        logging.info("Received message with size %d", len(data))
        await connection.write(data)


async def main():
    server = whiteproto.WhiteServer(HOST, PORT, PRESHARED_KEY)
    server.set_callback(on_connection)
    await server.start()
    await server.serve_forever()


asyncio.run(main())
