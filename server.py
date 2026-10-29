import asyncio
import struct
import time

from builder import build_response_header, builder_name, build_a_record
from file_func import get_dns_cache, write_in_cache
from help_function import fetch_from_upstream
from parsing import parse_packet


class DNSServerProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.cache = get_dns_cache()
        self.domain = None

    def connection_made(self, transport):
        self.transport = transport
        print("сервер запущен на 127.0.0.1:53")

    def datagram_received(self, data, addr):

        parsed_data = parse_packet(data)

        if not parsed_data['questions']:
            return

        domain = parsed_data['questions'][0]['qname']
        transaction_id = parsed_data['header']['id']

        print(f"запрос на домен: {domain}")
        print(parsed_data)
        if ".multiply." in domain:
            self.handle_multiply(domain, transaction_id, addr)
        else:
            asyncio.create_task(self.handle_forward(data, addr,domain))

    def handle_multiply(self, domain, transaction_id, addr):
        a, b = [x for x in domain.split('.') if x.isdigit()]
        result = min(255, int(a) * int(b))
        result_ip = f"127.0.0.{result}"
        header = build_response_header(transaction_id)
        question = builder_name(domain) + struct.pack("!HH", 1, 1)
        record = build_a_record(result_ip)
        self.transport.sendto(header + question + record, addr)

    async def handle_forward(self, data, addr, domain,depth=0):
        target = "198.41.0.4"
        while True:
            a = await fetch_from_upstream(target, data)
            parsed_a = parse_packet(a)
            print("ответ", parsed_a)
            if len(parsed_a['answers']) != 0:
                answer = parsed_a['answers'][0]
                self.cache[domain] = {
                    'ip': answer['rdata'],
                    'expire_at': time.time() + answer['ttl']
                }
                break

            next_target = None
            for i in parsed_a['additionals']:
                if i['type'] == 1:
                    next_target = i['rdata']
                    break

            if next_target:
                target = next_target
            else:
                print("Тупик")
                answer = None
                break
        mass = [[d, info['ip'], info['expire_at']] for d, info in self.cache.items()]
        write_in_cache(mass)
        if answer:
            self.transport.sendto(a, addr)
        else:
            pass


async def run_server():
    print("Инициализация DNS-сервера")
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSServerProtocol(),
        local_addr=('127.0.0.1', 53)
    )

    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        transport.close()
        print("DNS-сервер остановлен.")


if __name__ == '__main__':
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        pass
