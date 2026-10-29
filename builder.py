import socket
import struct


def builder_name(domain):
    if not domain:
        return b'\x00'
    result = bytearray()
    mass = domain.split('.')

    for el in mass:
        length = len(el)
        result += bytes([length])
        result += el.encode('ascii')
    result += b'\x00'
    return bytes(result)


def build_response_header(transaction_id, flags=0x8180, qdcount=1, ancount=1, nscount=0, arcount=0):
    return struct.pack('!HHHHHH', transaction_id, flags, qdcount, ancount, nscount, arcount)


def build_a_record(ip_address):
    name_bytes = struct.pack('!H', 0xC00C)
    meta_bytes = struct.pack('!HHIH', 1, 1, 60, 4)
    rdata_bytes = socket.inet_aton(ip_address)
    return name_bytes + meta_bytes + rdata_bytes
