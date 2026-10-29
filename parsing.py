import struct
import socket

raw_dump = """0000   14 ac 60 35 11 8f 80 af ca 7e ea d9 08 00 45 00
0010   00 9f b7 2a 40 00 40 11 6c 80 0a 01 01 01 0a 01
0020   01 a1 00 35 ef dd 00 8b c9 c3 90 c6 81 80 00 01
0030   00 06 00 00 00 01 02 76 6b 03 63 6f 6d 00 00 01
0040   00 01 c0 0c 00 01 00 01 00 00 00 e8 00 04 57 f0
0050   89 a4 c0 0c 00 01 00 01 00 00 00 e8 00 04 5d ba
0060   e1 c2 c0 0c 00 01 00 01 00 00 00 e8 00 04 57 f0
0070   81 85 c0 0c 00 01 00 01 00 00 00 e8 00 04 57 f0
0080   84 4e c0 0c 00 01 00 01 00 00 00 e8 00 04 57 f0
0090   84 48 c0 0c 00 01 00 01 00 00 00 e8 00 04 57 f0
00a0   84 43 00 00 29 0f a0 00 00 00 00 00 00

"""
clean_hex = "".join(line.split(maxsplit=1)[1] for line in raw_dump.strip().split('\n'))

clean_hex = clean_hex.replace(" ", "")

packet_bytes = bytes.fromhex(clean_hex)

dns_payload = packet_bytes[42:]


def parse_header(packet, offset):
    header = struct.unpack('!HHHHHH', packet[offset:offset + 12])
    transaction_id = header[0]
    flags = header[1]
    qdcount = header[2]
    ancount = header[3]
    return ({"id": transaction_id,
             "flags": flags,
             "qdcount": qdcount,
             "ancount": ancount,
             "nscount": header[4],
             "arcount": header[5]
             }, offset + 12)


def parse_question(packet, offset):
    qname, offset = parse_name(packet, offset)

    qtype, qclass = struct.unpack('!HH', packet[offset: offset + 4])
    offset += 4
    return {'qname': qname, 'qtype': qtype, 'qclass': qclass}, offset


def parse_name(packet, offset):
    labels = []
    while True:
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        elif length >= 192:
            pointer_bytes = packet[offset: offset + 2]
            pointer = struct.unpack('!H', pointer_bytes)[0] & 0x3FFF
            pointed_name = parse_name(packet, pointer)[0]
            labels.append(pointed_name)
            offset += 2
            break
        else:
            offset += 1
            word = packet[offset: offset + length]
            labels.append(word.decode('ascii'))

            offset += length
    return ".".join(labels), offset


def parse_rr(packet, offset):
    name, offset = parse_name(packet, offset)

    rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', packet[offset: offset + 10])
    offset += 10

    rdata_bytes = packet[offset: offset + rdlength]

    if rtype == 1 and rdlength == 4:
        rdata = socket.inet_ntoa(rdata_bytes)
    else:
        rdata = rdata_bytes

    offset += rdlength

    return {
        'name': name,
        'type': rtype,
        'class': rclass,
        'ttl': ttl,
        'rdata': rdata
    }, offset


def parse_packet(packet):
    offset = 0
    header, offset = parse_header(packet, offset)
    questions = []
    for _ in range(header["qdcount"]):
        question, offset = parse_question(packet, offset)
        questions.append(question)

    answers = []
    for _ in range(header["ancount"]):
        answer, offset = parse_rr(packet, offset)
        answers.append(answer)

    authorities = []
    for _ in range(header.get("nscount", 0)):
        authority, offset = parse_rr(packet, offset)
        authorities.append(authority)

    additionals = []
    for _ in range(header.get("arcount", 0)):
        additional, offset = parse_rr(packet, offset)
        additionals.append(additional)

    return {
        "header": header,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals
    }
