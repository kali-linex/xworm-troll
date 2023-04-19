import argparse
import xworm

p = argparse.ArgumentParser()
p.add_argument('-k', '--key', default='<123456789>')
p.add_argument('-o', '--output', type=argparse.FileType('wb'))
p.add_argument('infile', metavar = 'INFILE', type=argparse.FileType('r'))

args = p.parse_args()
xworm.write_all_to_stream(xworm.read_packet_file(args.infile), args.key.encode('utf-8'), args.output)
args.infile.close()
args.output.close()