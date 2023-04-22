import argparse
import xworm
import socket
import io
import threading
import Cryptodome

# BONSAIII
def xrecv(sock, dlen):
    chunks = []
    bytes_recd = 0
    while bytes_recd < dlen:
        chunk = sock.recv(min(dlen - bytes_recd, 2048))
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        chunks.append(chunk)
        bytes_recd = bytes_recd + len(chunk)
    return b''.join(chunks)

def xrecvtill0(sock):
    c = b''
    while (a := sock.recv(1)) != b'\0':
        c += a
    return c

p = argparse.ArgumentParser()
p.add_argument('-k', '--key', default='<123456789>')
p.add_argument('host', metavar='HOST')
p.add_argument('port', metavar='PORT', type=int)

args = p.parse_args()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((args.host, args.port))

def dumper():
    while True:
        l = int(xrecvtill0(s))
        d = xrecv(s, l)
        print(xworm.decrypt(d, args.key.encode('utf-8')))

threading.Thread(None, dumper).start()

while True:
    l = input('>> ')
    b = io.BytesIO()
    xworm.write_all_to_stream(xworm.parse_packet_line(l), args.key.encode('utf-8'), b)
    s.sendall(b.getbuffer())
