# AES-GCM-SIV PoC generator from a Mitra-generated polyglot
# Note: requires block alignment

import sys
import argparse

load('gcm_siv.sage')

parser = argparse.ArgumentParser(description="Turn a non-overlapping, block-aligned polyglot into a dual AES-GCM-SIV ciphertext.")
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

key1_auth, key1_enc = derive_keys(key1, nonce)
key2_auth, key2_enc = derive_keys(key2, nonce)

while(1):
    T1_tmp = recover_POLYVAL(key1_enc, tag, nonce + unhexlify('00'*4))
    T2_tmp = recover_POLYVAL(key2_enc, tag, nonce + unhexlify('00'*4))
    if T1_tmp and T2_tmp:
        break
    tag = inc(tag)

T1 = byte_array_to_field_element_gcm_siv(T1_tmp)
T2 = byte_array_to_field_element_gcm_siv(T2_tmp)

num_blocks = len(fdata) // 16
m1 = [fdata[i*16: i*16+16] for i in range(num_blocks)]
m2 = [fdata[i*16: i*16+16] for i in range(num_blocks)]

t = 2
num_blocks += t
m1 += [b'\0'*16 for _ in range(t)]
m2 += [b'\0'*16 for _ in range(t)]
M1 = [byte_array_to_field_element_gcm_siv(block) for block in m1]
M2 = [byte_array_to_field_element_gcm_siv(block) for block in m2]


controlled_m1 = []
controlled_m2 = []
start = 0
keep = controlled_m1
skip = controlled_m2
for end in cuts:
    keep += list(range(start, end))
    start = end
    keep, skip = skip, keep
keep += list(range(start, num_blocks))
skip += keep[-2:]

assert(len(controlled_m1 + controlled_m2) == num_blocks + t)

ciphertext, tag = siv(key1, key2, nonce, tag, num_blocks,
    m1, m2, controlled_m1, controlled_m2)

print(f'Key1: {hexlify(key1)}')
print(f'Key2: {hexlify(key2)}')
print(f'Nonce: {hexlify(nonce)}')
print(f'Ciphertext: {hexlify(ciphertext)}')
print(f'Tag: {hexlify(tag)}')

if args.dump_plaintexts:
    m1 = AES_GCM_SIV_decrypt(ciphertext, tag, key1, nonce)
    m2 = AES_GCM_SIV_decrypt(ciphertext, tag, key2, nonce)
    with open("siv1.bin", "wb") as f: f.write(m1)
    with open("siv2.bin", "wb") as f: f.write(m2)
