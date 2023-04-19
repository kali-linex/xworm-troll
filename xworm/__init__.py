import gzip
import struct
from abc import ABC, abstractmethod
import io

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import hashlib
import importlib


log = lambda *args: None


class AbstractPacket(ABC):
    @abstractmethod
    def write_bytes(self, into: io.IOBase):
        ...

    def get_bytes(self):
        b = io.BytesIO()
        self.write_bytes(b)
        return b.getbuffer().tobytes()
    
    def __str__(self):
        return type(self).__name__


class Packet(AbstractPacket):
    def __init__(self, *data: list[bytes]):
        self.data = data

    def write_bytes(self, into):
        into.write(b'<Xwormmm>'.join(self.data))
    
    def __str__(self):
        items = []
        for d in self.data:
            try:
                if b'\0' in d:
                    raise ValueError()
                items.append(d.decode('utf-8'))
            except:
                items.append('<binary data>')
        return f'{type(self).__qualname__}: {" ".join(items)}'


def write_all_to_stream(packets: list[AbstractPacket], key: bytes, into: io.RawIOBase):
    key = hashlib.md5(key).digest()
    crypto = AES.new(key, AES.MODE_ECB)
    for p in packets:
        encrypted = crypto.encrypt(pad(p.get_bytes(), 16))
        into.write(str(len(encrypted)).encode('utf-8') + b'\0')
        into.write(encrypted)


def str_to_arg(s: str):
    if s.startswith('gz:'):
        with open(s[3:], 'rb') as f:
            return compress(f.read())
    elif s.startswith('in:'):
        with open(s[3:], 'rb') as f:
            return (f.read())
    return s.encode('utf-8')


def parse_packet_line(l: str) -> list[AbstractPacket]:
    if l[0] == '#' or l.strip() == '':
        return []
    l = l.strip('\n')
    embedded_python_env = {
        'x': importlib.import_module('xworm'),
        'pv3': importlib.import_module('xworm.packets.v3'),
    }
    if l.startswith('@INCLUDE '):
        with open(l[9:], 'r') as f:
            return read_packet_file(f)
    elif l.startswith('@EVALL '):
        # yes, we're going to eval python code
        return eval(l[7:], embedded_python_env)
    elif l.startswith('@EVAL '):
        # make a single element list for convenience
        return [eval(l[6:], embedded_python_env)]
    return [Packet(*map(str_to_arg, l.split(';')))]


def read_packet_file(stream):
    packets = []
    for l in stream:
        packets += parse_packet_line(l)
    log('>>', packets)
    return packets        


def compress(data):
    return struct.pack('<L', len(data)) + gzip.compress(data)