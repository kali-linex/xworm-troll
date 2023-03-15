from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from hashlib import md5
import gzip
import struct
import argparse

def get_aes_key(key) -> bytes:
    return md5(key).digest()

def arg_to_bytes(arg: str) -> bytes:
    if arg.startswith('gz:'):
        with open(arg[3:], 'rb') as f:
            data = f.read()
        return struct.pack('<L', len(data)) + gzip.compress(data)
    elif arg.startswith('inc:'):
        with open(arg[4:], 'rb') as f:
            return f.read()
    return arg.encode('utf-8')

parser = argparse.ArgumentParser(description='A program that handles XWorm packets. Go and do some exploiting.')
parser.add_argument('-k', '--key', default='<123456789>')
parser.add_argument('-e', '--encrypt', metavar=('OUTFILE', 'CMD'), nargs='+')
parser.add_argument('-a', '--append', action='store_true')
parser.add_argument('-d', '--decrypt', metavar=('INFILE', 'OUTFILE'), nargs=2)
args = parser.parse_args()

aes = AES.new(md5(args.key.encode('utf-8')).digest(), AES.MODE_ECB)

if args.encrypt:
    outfile, *cmds = args.encrypt
    plaintext_packet = b'<Xwormmm>'.join(map(arg_to_bytes, cmds))
    enc_packet = aes.encrypt(pad(plaintext_packet, 16))
    with open(outfile, 'ab' if args.append else 'wb') as f:
        f.write(str(len(enc_packet)).encode('utf-8') + b'\0')
        f.write(enc_packet)