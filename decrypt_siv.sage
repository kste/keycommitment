# AES-GCM-SIV PoC decryptor

import sys
import argparse

load('gcm_siv.sage')

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

    m1 = AES_GCM_SIV_decrypt(ciphertext, tag, key1, nonce)
    m2 = AES_GCM_SIV_decrypt(ciphertext, tag, key2, nonce)

    with open("siv1.bin", "wb") as f: f.write(m1)
    with open("siv2.bin", "wb") as f: f.write(m2)
