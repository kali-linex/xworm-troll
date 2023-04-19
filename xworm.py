import gzip
import struct
from abc import ABC, abstractmethod
import io

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import hashlib


class AbstractPacket(ABC):
    @abstractmethod
    def write_bytes(self, into: io.IOBase):
        ...

    def get_bytes(self):
        b = io.BytesIO()
        self.write_bytes(b)
        return b.getbuffer().tobytes()


class Packet(AbstractPacket):
    def __init__(self, *data: list[bytes]):
        self.data = data

    def write_bytes(self, into):
        into.write(b'<Xwormmm>'.join(self.data))


def write_all_to_stream(packets: list[AbstractPacket], key: bytes, into: io.RawIOBase):
    key = hashlib.md5(key).digest()
    crypto = AES.new(key, AES.MODE_ECB)
    for p in packets:
        encrypted = crypto.encrypt(pad(p.get_bytes(), 16))
        into.write(str(len(encrypted)).encode('utf-8') + b'\0')
        into.write(encrypted)


def str_to_arg(s: str):
    if s.startswith('gz:'):
        with open(s[3:], 'r') as f:
            return compress(f.read())
    elif s.startswith('in:'):
        with open(s[3:], 'r') as f:
            return (f.read())
    return s.encode('utf-8')


def parse_packet_line(l: str) -> list[AbstractPacket]:
    if l.startswith('@INCLUDE '):
        with open(l[9:], 'r') as f:
            return read_packet_file(f)
    return [Packet(*map(str_to_arg, l.split(';')))]


def read_packet_file(stream):
    packets = []
    for l in stream:
        packets += parse_packet_line(l)
    return packets        


def compress(data):
    return struct.pack('<L', len(data)) + gzip.compress(data)