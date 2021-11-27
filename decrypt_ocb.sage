# AES-OCB3 PoC decryptor

import sys
import argparse

load('ocb.sage')

if __name__=='__main__':
    fname = sys.argv[1]
    with open(fname, "rb") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        l = line.split(b": ")
        if l[1].startswith(b"b'") and l[1][-1] == 39:
            l[1] = l[1][2:-1]
        vars()[l[0].decode("utf-8").lower()] = l[1].strip().decode("utf-8")

    for v in ["key1", "key2", "nonce", "ciphertext", "tag"]:
        vars()[v] = unhexlify(vars()[v])

    cipher1 = AES.new(key1, AES.MODE_OCB, nonce=nonce)
    cipher2 = AES.new(key2, AES.MODE_OCB, nonce=nonce)

    m1 = cipher1.decrypt_and_verify(ciphertext, tag)
    m2 = cipher2.decrypt_and_verify(ciphertext, tag)

    with open("ocb1.bin", "wb") as f: f.write(m1)
    with open("ocb2.bin", "wb") as f: f.write(m2)
