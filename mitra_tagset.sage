# Sets the tag of an AES-GCM PoC output from Mitra's tool.

import sys
import argparse

load('gcm.sage')

parser = argparse.ArgumentParser(description="Sets the tag in a GCM output file from Mitra's GCM tool.")
parser.add_argument('gcm_file',
    help="Input file generated by Mitra's GCM tool.")
parser.add_argument('-t', '--tag', default=unhexlify('04'*16),
    help="Tag - default: 04*16 .")
parser.add_argument('-i', '--index', default=0,
    help="Index of correction blocks.")
parser.add_argument('-p', '--dump_plaintexts', default=False, action="store_true",
    help="Dump decrypted payloads.")


args = parser.parse_args()

fn = args.gcm_file
wanted_tag = args.tag
index = int(args.index)

with open(fn, "rb") as f:
    lines = f.readlines()

for line in lines:
    line = line.strip()
    l = line.split(b": ")
    vars()[l[0].decode("utf-8")] = l[1].strip().decode("utf-8")

for v in ["key1", "key2", "adata", "nonce", "ciphertext", "tag"]:
    vars()[v] = unhexlify(vars()[v])

assert len(ciphertext) % 16 == 0
assert len(adata) % 16 == 0

# we just discard the previous value
tag = wanted_tag

ad_str = adata
num_ad_blocks = len(ad_str) // 16
ad_blocks = [ad_str[i*16: i*16+16] for i in range(num_ad_blocks)]

ct_str = ciphertext
num_ct_blocks = len(ct_str) // 16
ct_blocks = [ct_str[i*16: i*16+16] for i in range(num_ct_blocks)]

# In practice, we can put these 2 blocks anywhere - even in AD -
# but it's not supported here.
correction_indices = [
    num_ad_blocks + index,
    num_ad_blocks + index + 1
]

ad_blocks, ct_blocks = gcm(key1, key2, nonce, tag,
    correction_indices,
    num_ct_blocks, ct_blocks,
    num_ad_blocks, ad_blocks)

additional_data = b''.join(ad_blocks)
ciphertext = b''.join(ct_blocks)

print(f'Key1: {hexlify(key1)}')
print(f'Key2: {hexlify(key2)}')
print(f'Nonce: {hexlify(nonce)}')
print(f'AdditionalData: {hexlify(additional_data)}')
print(f'Ciphertext: {hexlify(ciphertext[:32])}')
print(f'Tag: {hexlify(tag)}')

if args.dump_plaintexts:
    cipher = AES.new(key1, AES.MODE_GCM, nonce=nonce)
    _ = cipher.update(additional_data)
    m1 = cipher.decrypt_and_verify(ciphertext, tag)

    cipher = AES.new(key2, AES.MODE_GCM, nonce=nonce)
    _ = cipher.update(additional_data)
    m2 = cipher.decrypt_and_verify(ciphertext, tag)
    with open("gcm1.bin", "wb") as f: f.write(m1)
    with open("gcm2.bin", "wb") as f: f.write(m2)
