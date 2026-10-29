import socket
import asyncio


async def fetch_from_upstream(target_ip, query_bytes):
    loop = asyncio.get_running_loop()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.setblocking(False)

    try:
        sock.connect((target_ip, 53))
        sock.send(query_bytes)
        response_bytes = await loop.sock_recv(sock, 4096)

        return response_bytes
    finally:
        sock.close()
