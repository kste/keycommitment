"""
This modules contains a basic AES-GCM-SIV implementation and some
GCM-SIV specific utility functions, which will be used
for the attack.
"""
from Crypto.Cipher import AES
import struct

load('util.sage')

F2.<x> = GF(2)[];
p = x^128 + x^127 + x^126 + x^121 + 1;
F = GF(2^128, 'x', modulus=p)

def AES_GCM_SIV_encrypt(plaintext, key, nonce):
    """
    Encrypt with AES-GCM-SIV as described in https://datatracker.ietf.org/doc/rfc8452
    """

    message_auth_key, message_enc_key = derive_keys(key, nonce)
    plaintext_length = len(plaintext)

    len_block = unhexlify('00'*8) + struct.pack(b'<Q', len(plaintext) * 8)

    # Pad plaintext
    if len(plaintext) % 16 != 0:
        plaintext = plaintext + b'\x00'*(16 - len(plaintext) % 16)

    S = POLYVAL(message_auth_key, plaintext + len_block)

    final_S = b''
    for i in range(12):
        final_S += bytes([S[i] ^^ nonce[i]])
    final_S += S[12:15] + bytes([S[15] & 0x7f])

    tag = block_aes(final_S, message_enc_key)
    counter_block = tag[:15] + bytes([tag[15] | 0x80])
    ciphertext = AES_CTR(message_enc_key, counter_block, plaintext)
    return (ciphertext[:plaintext_length], tag)

def AES_GCM_SIV_decrypt(ciphertext, expected_tag, key, nonce):
    """
    Decrypt with AES-GCM-SIV as described in https://datatracker.ietf.org/doc/rfc8452
    """

    message_auth_key, message_enc_key = derive_keys(key, nonce)


    counter_block = expected_tag[:15] + bytes([expected_tag[15] | 0x80])
    plaintext = AES_CTR(message_enc_key, counter_block, ciphertext)
    len_block = unhexlify('00'*8) + struct.pack(b'<Q', len(plaintext) * 8)

    # Pad plaintext
    if len(plaintext) % 16 != 0:
        plaintext = plaintext + b'\x00'*(16 - len(plaintext) % 16)

    S = POLYVAL(message_auth_key, plaintext + len_block)
    final_S = b''
    for i in range(12):
        final_S += bytes([S[i] ^^ nonce[i]])
    final_S += S[12:15] + bytes([S[15] & 0x7f])

    tag = block_aes(final_S, message_enc_key)
    if expected_tag != tag:
        return False

    return plaintext[:len(ciphertext)]

def POLYVAL(key, input_value):
    input_blocks = [byte_array_to_field_element_gcm_siv(input_value[i*16:i*16+16]) for i in range(len(input_value) // 16)]
    H = byte_array_to_field_element_gcm_siv(key)

    xinv128 = F(x^127 + x^124 + x^121 + x^114 + 1)
    result = F(0)

    for block in input_blocks:
        result = (result + block)*H*xinv128

    return field_element_to_byte_array_gcm_siv(result)

def AES_CTR(key, counter_block, plaintext):
    input_blocks = [plaintext[i*16:i*16+16] for i in range(len(plaintext) // 16)]
    ciphertext = b''

    for block in input_blocks:
        keystream_block = block_aes(counter_block, key)
        ciphertext += xor_block(keystream_block, block)
        counter_block = inc(counter_block)
    return ciphertext

def inc(counter_block):
    counter = struct.unpack(b'<L', counter_block[0:4])[0]
    counter = (counter + 1) & 0xffffffff
    return struct.pack(b'<L', counter) + counter_block[4:]

def derive_keys(key, nonce):
    message_authentication_key = block_aes(unhexlify('00000000') + nonce, key)[:8] +\
                                 block_aes(unhexlify('01000000') + nonce, key)[:8]
    message_encryption_key = block_aes(unhexlify('02000000') + nonce, key)[:8] +\
                             block_aes(unhexlify('03000000') + nonce, key)[:8]
    return message_authentication_key, message_encryption_key

def recover_POLYVAL(key, tag, nonce):
    tmp = block_aes_inverse(tag, key)

    if tmp[15] & 0x80 != 0:
        return False

    return xor_block(tmp, nonce)

def testvector():
    tag_size = 16
    plaintext = unhexlify('')
    key = unhexlify('01000000000000000000000000000000')
    nonce = unhexlify('030000000000000000000000')
    expected_ct = unhexlify('dc20e2d83f25705bb49e439eca56de25')
    ct, tag = AES_GCM_SIV_encrypt(plaintext, key, nonce)

    assert(ct == expected_ct[:len(plaintext)])
    assert(tag == expected_ct[-tag_size:])

    plaintext = unhexlify('0100000000000000')
    key = unhexlify('01000000000000000000000000000000')
    nonce = unhexlify('030000000000000000000000')
    expected_ct = unhexlify('b5d839330ac7b786578782fff6013b815b287c22493a364c')
    ct, tag = AES_GCM_SIV_encrypt(plaintext, key, nonce)
    assert(ct == expected_ct[:len(plaintext)])
    assert(tag == expected_ct[-tag_size:])

    plaintext = unhexlify('010000000000000000000000')
    key = unhexlify('01000000000000000000000000000000')
    nonce = unhexlify('030000000000000000000000')
    expected_ct = unhexlify('7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639')
    ct, tag = AES_GCM_SIV_encrypt(plaintext, key, nonce)
    assert(ct == expected_ct[:len(plaintext)])
    assert(tag == expected_ct[-tag_size:])

    plaintext = unhexlify('0100000000000000000000000000000002000000000000000000000000000000')
    key = unhexlify('01000000000000000000000000000000')
    nonce = unhexlify('030000000000000000000000')
    expected_ct = unhexlify('84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667cd86847bf6155ff')
    ct, tag = AES_GCM_SIV_encrypt(plaintext, key, nonce)
    assert(ct == expected_ct[:len(plaintext)])
    assert(tag == expected_ct[-tag_size:])
