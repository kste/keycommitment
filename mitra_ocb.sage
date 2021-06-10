# AES-OCB3 PoC generator from a Mitra-generated polyglot
# Note: requires block alignment

import sys
import argparse

load('ocb.sage')

parser = argparse.ArgumentParser(description="Turn a non-overlapping, block-aligned polyglot into a dual AES-OCB3 ciphertext.")
parser.add_argument('polyglot',
    help="input polyglot - requires special naming like 'P(10-5c).png.rar'.")
parser.add_argument('-k', '--keys', nargs=2, default=['01'*16, '02'*16],
    help="encryption keys - default: 01* / 02*.")
parser.add_argument('-n', '--nonce', default='03'*12,
    help="nonce - default: 03*.")
parser.add_argument('-t', '--tag', default='04'*16,
    help="nonce - default: 04*.")
parser.add_argument('-p', '--dump_plaintexts', default=False, action="store_true",
    help="Dump decrypted payloads.")

args = parser.parse_args()

fn = args.polyglot
key1, key2 = args.keys
key1 = unhexlify(key1)
key2 = unhexlify(key2)
nonce = unhexlify(args.nonce)
tag = unhexlify(args.tag)

cuts = fn[fn.find("(") + 1:]
cuts = cuts[:cuts.find(")")]
cuts = cuts.split("-")
cuts = [int(i, 16)//16 for i in cuts]

if len(cuts) < 1:
    printf("Invalid cuts parameters from filename - aborting.")
    sys.exit()

with open(fn, "rb") as f:
    fdata = f.read()

content_length = len(fdata) / 16
m1 = [fdata[i*16: i*16+16] for i in range(content_length)]
m2 = [fdata[i*16: i*16+16] for i in range(content_length)]

t = 270 # 256 is ~50%, 270 is 99%
m = content_length + t + 1

m1 += [b'\0'*16 for _ in range(t+1)]
m2 += [b'\0'*16 for _ in range(t+1)]

controlled_m1 = []
controlled_m2 = []
start = 0

keep = controlled_m1
skip = controlled_m2
for end in cuts:
    keep += list(range(start, end))
    start = end
    keep, skip = skip, keep
keep += list(range(start, content_length))

assert(len(controlled_m1 + controlled_m2) == content_length)

ciphertext, tag = ocb(key1, key2, nonce, tag, 
    content_length, t, m,
    m1, m2,
    controlled_m1, controlled_m2)

print(f'Key1: {hexlify(key1)}')
print(f'Key2: {hexlify(key2)}')
print(f'Nonce: {hexlify(nonce)}')
print(f'Ciphertext: {hexlify(ciphertext)}')
print(f'Tag: {hexlify(tag)}')

if args.dump_plaintexts:
    cipher1 = AES.new(key1, AES.MODE_OCB, nonce=nonce)
    cipher2 = AES.new(key2, AES.MODE_OCB, nonce=nonce)
    m1 = cipher1.decrypt_and_verify(ciphertext, tag)
    m2 = cipher2.decrypt_and_verify(ciphertext, tag)
    with open("ocb1.bin", "wb") as f: f.write(m1)
    with open("ocb2.bin", "wb") as f: f.write(m2)
