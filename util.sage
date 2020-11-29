from Crypto.Cipher import AES
from binascii import hexlify, unhexlify

zero_block = unhexlify("00"*16)

def BlockAES(block, key):
    """
    Encrypt a 16-byte block using AES with the given key.
    """
    assert(len(block) == 16)
    aes = AES.new(key, AES.MODE_CBC, iv=unhexlify("00000000000000000000000000000000"))
    return aes.encrypt(block)

def byte_array_to_field_element(block):
    """
    Converts a 16-byte array to an element of GF(2^128).
    """
    assert(len(block) == 16)
    field_element = 0
    for i in range(128):
        if (block[i // 8] >> (7 - (i % 8))) & 1 == 1:
            field_element += x^i
    return F(field_element)

def field_element_to_byte_array(element):
    """
    Converts an element of GF(2^128) to a 16-byte array.
    """
    coeff = element.polynomial().coefficients(sparse=False)
    result = [0 for _ in range(16)]
    for i in range(len(coeff)):
        if coeff[i] == 1:
            result[i // 8] |= (1 << ((7 - i) % 8))
    return bytes(result)
