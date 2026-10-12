"""Write an original benign offline PCAP; never send a packet or open a socket."""

import argparse
import ipaddress
import struct
from pathlib import Path


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack("!" + str(len(data) // 2) + "H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(
    src: str, dst: str, sp: int, dp: int, seq: int, ack: int, flags: int, payload: bytes = b""
) -> bytes:
    a = ipaddress.ip_address(src).packed
    b = ipaddress.ip_address(dst).packed
    tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = a + b + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, a, b)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    eth = bytes.fromhex("0200000000020200000000010800")
    return eth + ip + tcp


def write(path: Path) -> None:
    src = "192.0.2.10"
    dst = "198.51.100.20"
    sp = 41000
    dp = 80
    request = b"GET /lab HTTP/1.1\r\nHost: lab.invalid\r\nUser-Agent: MiniSIEM-fixture\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nlab"
    packets = [
        packet(src, dst, sp, dp, 100, 0, 2),
        packet(dst, src, dp, sp, 500, 101, 18),
        packet(src, dst, sp, dp, 101, 501, 16),
        packet(src, dst, sp, dp, 101, 501, 24, request),
        packet(dst, src, dp, sp, 501, 101 + len(request), 24, response),
        packet(src, dst, sp, dp, 101 + len(request), 501 + len(response), 17),
        packet(dst, src, dp, sp, 501 + len(response), 102 + len(request), 17),
        packet(src, dst, sp, dp, 102 + len(request), 502 + len(response), 16),
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(packets):
            f.write(struct.pack("<IIII", 1735689600, i * 100000, len(p), len(p)) + p)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("output", type=Path)
    write(p.parse_args().output)
