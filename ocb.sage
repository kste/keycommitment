from Crypto.Cipher import AES
from functools import reduce

load('util.sage')
F2.<x> = GF(2)[];
p = x^128 + x^7 + x^2 + x + 1;
F = GF(2^128, 'x', modulus=p)

def double(block):
    """
    Takes a 16-byte block and applies double.
    """
    tmp = [0 for _ in range(16)]
    for i in range(15):
        tmp[i] = ((block[i] << 1) & 0xff) | (block[i+1] >> 7)
    tmp[15] = ((block[15] << 1) & 0xff) ^^ ((block[0] >> 7) * 135)
    return b''.join([bytes([i]) for i in tmp])

def compute_L_i(L_dollar, i):
    L = double(L_dollar)
    while(i&1 == 0):
        L = double(L)
        i = i >> 1
    return L

def derive_initial_L_and_offset(key, nonce):
    L_star = block_aes(zero_block, key)
    L_dollar = double(L_star)
    L_i = double(L_dollar)

    # Nonce derivation
    tmp_nonce = [0 for _ in range(16)]
    for i in range(len(nonce)):
        tmp_nonce[16 - len(nonce) + i] = nonce[i]
    tmp_nonce[16 - len(nonce) - 1] = 0x01
    bottom = tmp_nonce[15] & 0x3f
    tmp_nonce[15] &= 0xC0
    ktop = block_aes(b''.join([bytes([i]) for i in tmp_nonce]), key)
    tmp_bytes = b''
    for i in range(8):
        tmp_bytes += bytes([ktop[i] ^^ ktop[i + 1]])
    stretch = ktop + tmp_bytes
    byteshift = bottom//8
    bitshift = bottom%8

    offset = [0 for _ in range(16)]
    for i in range(16):
        if bitshift != 0:
            offset[i] = ((stretch[i + byteshift] << bitshift) & 0xff) | (stretch[i + byteshift + 1] >> (8 - bitshift))
        else:
            offset[i] = stretch[i + byteshift]

    offset = b''.join([bytes([i]) for i in offset])
    return L_dollar, offset

def block_encrypt_decrypt(block, key1, key2, offset1, offset2):
    """
    This encrypts a block of 16-bytes first with key1 and using offset1, then
    will decrypt it with key2 using offset2.
    """
    tmp = xor_block(offset1, block_aes(xor_block(block, offset1), key1))
    return xor_block(offset2, block_aes_inverse(xor_block(tmp, offset2), key2))

def ocb(key1, key2, nonce, tag,
        content_length, t, m,
        m1, m2,
        controlled_m1, controlled_m2):

    # Generate all the masks
    L1_dollar, offset1 = derive_initial_L_and_offset(key1, nonce)
    offsets1 = [offset1]
    for i in range(m):
        L1_i = compute_L_i(L1_dollar, i + 1)
        offsets1.append(xor_block(offsets1[i], L1_i))
    offsets1 = offsets1[1:]

    L2_dollar, offset2 = derive_initial_L_and_offset(key2, nonce)
    offsets2 = [offset2]
    for i in range(m):
        L2_i = compute_L_i(L2_dollar, i + 1)
        offsets2.append(xor_block(offsets2[i], L2_i))
    offsets2 = offsets2[1:]

    # Compute the checksum we need to have in order to get the correct tag with
    # each key.
    T1 = xor_block(xor_block(block_aes_inverse(tag, key1), L1_dollar), offsets1[-1])
    T2 = xor_block(xor_block(block_aes_inverse(tag, key2), L2_dollar), offsets2[-1])


    # We have to fix the uncontrolled blocks in m1/m2 so they encrypt to the same ciphertext as m1/m2.
    for idx in controlled_m1:
        m2[idx] = block_encrypt_decrypt(m1[idx], key1, key2, offsets1[idx], offsets2[idx])
    for idx in controlled_m2:
        m1[idx] = block_encrypt_decrypt(m2[idx], key2, key1, offsets2[idx], offsets1[idx])

    # Modify m1 in order to get the correct tag value. This guarantees that as long
    # as the checksum is 0 for m1[m - t] ... m1[m] the tag will be correct.
    m1[m - t - 1] = reduce(lambda x, y: xor_block(x, y), m1[:(m - t - 1)] + [T1])
    m2[m - t - 1] = block_encrypt_decrypt(m1[m - t - 1], key1, key2,
                                          offsets1[m - t - 1],
                                          offsets2[m - t - 1])

    # Update target checksum for the free blocks after fixing the first blocks of m2.
    T2 = reduce(lambda x, y: xor_block(x, y), m2[:(m - t)] + [T2])

    # Generate the gamma values
    m2_blocks_zero = []
    m2_blocks_one = []
    gamma_0 = []
    for i in range(t//2):
        # Encrypt and decrypt a pair of two all zero message blocks and XOR them.
        # Note that any pair of messages which are equal would work here. The only
        # condition here as that if we sum up all the blocks the checksum stays
        # zero.
        tmp1 = block_encrypt_decrypt(zero_block, key1, key2,
                                     offsets1[m - t + 2*i],
                                     offsets2[m - t + 2*i])

        tmp2 = block_encrypt_decrypt(zero_block, key1, key2,
                                     offsets1[m - t + 2*(i + 1) - 1],
                                     offsets2[m - t + 2*(i + 1) - 1])

        m2_blocks_zero.append(tmp1)
        m2_blocks_zero.append(tmp2)
        gamma_0.append(byte_array_to_bitvector(xor_block(tmp1, tmp2)))

    gamma_1 = []
    for i in range(t//2):
        # Encrypt and decrypt a pair of two all one message blocks and XOR them.
        tmp1 = block_encrypt_decrypt(one_block, key1, key2,
                                     offsets1[m - t + 2*i],
                                     offsets2[m - t + 2*i])

        tmp2 = block_encrypt_decrypt(one_block, key1, key2,
                                     offsets1[m - t + 2*(i + 1) - 1],
                                     offsets2[m - t + 2*(i + 1) - 1])

        m2_blocks_one.append(tmp1)
        m2_blocks_one.append(tmp2)
        gamma_1.append(byte_array_to_bitvector(xor_block(tmp1, tmp2)))

    # Construct the system of linear equations to find the correct
    # combination of pairs which we have to use in m2 to get the
    # correct tag.
    equations = []

    # Equations to ensure that summing up will gives us the correct
    # checksum in the end.
    for bit_pos in range(128):
        tmp = []
        for i in range(t // 2):
            tmp.append(gamma_0[i][bit_pos])
            tmp.append(gamma_1[i][bit_pos])
        equations.append(tmp)

    # Equations to ensure that either the zero pair or one pair is used.
    for i in range(t // 2):
        tmp = [0] * 2*i + [1, 1] + [0] * (t - 2*i - 2)
        equations.append(tmp)

    A = matrix(GF(2), equations)
    # Right-hand side of the equation is just the target checksum, and
    # all 1 for ensuring that at each index only one pair is valid.
    b = vector(GF(2), byte_array_to_bitvector(T2) + [1]*(t//2))

    try:
        solution = A.solve_right(b)
    except ValueError:
        print('Could not find a solution for the system of linear equations. '
              'You can try increasing the value t or a different combination of keys/nonce.')
        exit(1)

    # Set the final message depending on the solution to the system of
    # linear equations.
    for i in range(t):
        if solution[2 * (i // 2)] == 1:
            m1[m - t + i] = zero_block
            m2[m - t + i] = m2_blocks_zero[i]
        else:
            m1[m - t + i] = one_block
            m2[m - t + i] = m2_blocks_one[i]
    # Check if this message will give us the correct tag.
    message1 = b"".join([block for block in m1])
    cipher = AES.new(key1, AES.MODE_OCB, nonce=nonce)
    ct1, tag1 = cipher.encrypt_and_digest(message1)

    message2 = b"".join([block for block in m2])
    cipher = AES.new(key2, AES.MODE_OCB, nonce=nonce)
    ct2, tag2 = cipher.encrypt_and_digest(message2)

    # Check if everything is correct.
    assert(ct1 == ct2)
    assert(tag1 == tag2)

    return ct1, tag1


if __name__ == "__main__" and __file__ == "ocb.sage.py":
# Construct ciphertext which works for two keys
    key1 = unhexlify('01'*16)
    key2 = unhexlify('02'*16)
    nonce = unhexlify('03'*12)
    tag = unhexlify('04'*16)

# Fix the message length so we can compute all the mask values needed in advance.
# For the attack we need to control t + 1 message blocks. For the sample attack
# we assume that the blocks containing the actual message content are in the beginning
# while the blocks used for forcing a correct tag are in the end. There is no restriction
# for this, but it allows to keep the implementation here simpler.
#
# t should be ~256 to have a good probability of finding a solution.
    content_length = 6
    t = 256
    m = content_length + t + 1

# Set the value of the two messages. Note that most of these values will be overwritten.
    m1 = [b'\xaa'*16 for _ in range(m)]
    m2 = [b'\xbb'*16 for _ in range(m)]

# In order to get the correct ciphertext, we will always need to control
# either the block in m1 or m2. The following indices determine which
# blocks of plaintext are preserved either in m1 or m2.
    controlled_m1 = [0, 1, 2]
    controlled_m2 = [3, 4, 5]
    assert(len(controlled_m1 + controlled_m2) == content_length)

    ciphertext, tag = ocb(key1, key2, nonce, tag,
        content_length, t, m,
        m1, m2,
        controlled_m1, controlled_m2)

    print(f'Key1: {hexlify(key1)}')
    print(f'Key2: {hexlify(key2)}')
    print(f'Nonce: {hexlify(nonce)}')
    print(f'Ciphertext: {hexlify(ciphertext[:32])}...')
    print(f'Tag: {hexlify(tag)}')
