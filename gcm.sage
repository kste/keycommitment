from Crypto.Cipher import AES

load('util.sage')

# The finite field used in GCM
F2.<x> = GF(2)[];
p = x^128 + x^7 + x^2 + x + 1;
F = GF(2^128, 'x', modulus=p)

# A complete example for GCM which allows to construct a single ciphertext + tag
# which can be decrypted under two different keys.
#

def gcm(key1, key2, nonce, tag,
        correction_indices,
        num_ct_blocks, ct_blocks,
        num_ad_blocks, ad_blocks):
    # Derive some of the constants we need to compute the tag.
    H1 = byte_array_to_field_element(block_aes(zero_block, key1))
    H2 = byte_array_to_field_element(block_aes(zero_block, key2))
    tag_mask1 = byte_array_to_field_element(block_aes(nonce + unhexlify('00000001'), key1))
    tag_mask2 = byte_array_to_field_element(block_aes(nonce + unhexlify('00000001'), key2))
    len_block = byte_array_to_field_element(unhexlify(hex(num_ad_blocks*128)[2:].zfill(16)) + unhexlify(hex(num_ct_blocks*128)[2:].zfill(16)))

    # Convert additional data, ciphertext blocks and target tag value to field elements.
    A = [byte_array_to_field_element(block) for block in ad_blocks]
    C = [byte_array_to_field_element(block) for block in ct_blocks]
    TAG_VALUE = byte_array_to_field_element(tag)

    # Concatenate additonal data and ciphertext blocks for equations below.
    AC = A + C
    num_blocks = num_ad_blocks + num_ct_blocks

    # Construct two linear equations:
    # 1) Ensures that the tag values are equal for both keys.
    # 2) Forces a specific tag value.
    sum_h1 = sum([H1^(num_blocks + 1 - i) * AC[i] for i in range(num_blocks) if i not in correction_indices])
    sum_h2 = sum([H2^(num_blocks + 1 - i) * AC[i] for i in range(num_blocks) if i not in correction_indices])

    b1 = sum_h1 + sum_h2 + len_block*H1 + tag_mask1 + len_block*H2 + tag_mask2
    b2 = TAG_VALUE + tag_mask1 + H1*len_block + sum_h1

    a00 = H1^(num_blocks - correction_indices[0] + 1) + H2^(num_blocks - correction_indices[0] + 1)
    a01 = H1^(num_blocks - correction_indices[1] + 1) + H2^(num_blocks - correction_indices[1] + 1)
    a10 = H1^(num_blocks - correction_indices[0] + 1)
    a11 = H1^(num_blocks - correction_indices[1] + 1)

    # Solve system of linear equations
    A = Matrix(F, [[a00, a01], [a10, a11]])
    b = vector(F, [b1, b2])
    AC[correction_indices[0]], AC[correction_indices[1]] = A.solve_right(b)

    # Place the solution in the original additional data and/or ciphertext blocks.
    for cor_idx in correction_indices:
        if cor_idx < num_ad_blocks:
            ad_blocks[cor_idx] = field_element_to_byte_array(AC[cor_idx])
        else:
            ct_blocks[cor_idx - num_ad_blocks] = field_element_to_byte_array(AC[cor_idx])

    # Recompute tag and check that they are equal.
    tag1 = sum([H1^(num_blocks + 1 - i) * AC[i] for i in range(num_blocks)]) + H1*len_block + tag_mask1
    tag2 = sum([H2^(num_blocks + 1 - i) * AC[i] for i in range(num_blocks)]) + H2*len_block + tag_mask2
    assert(tag1 == tag2)

    return ad_blocks, ct_blocks


if __name__ == "__main__" and __file__ == "gcm.sage.py":
    # The following variables can be of any value:
    key1 = unhexlify('01'*16)
    key2 = unhexlify('02'*16)
    nonce = unhexlify('03'*12)
    tag = unhexlify('04'*16)

# Ciphertext is given as 16-byte blocks.
    num_ct_blocks = 6
    ct_blocks = [b'\xcc'*16 for _ in range(num_ct_blocks)]

# Additional data is given as 16-byte blocks.
    num_ad_blocks = 2
    ad_blocks = [b'\xaa'*16 for _ in range(num_ad_blocks)]

# We need to control 2 blocks in order to be able to solve system of linear equations, which
# can be either in the additional data or the ciphertext part. Note that if we don't fix the
# tag it would also be possible to use a single block.
#
# Indices for additional data are 0...num_ad_blocks - 1
# Indices for ciphertext are num_ad_blocks..num_ad_blocks+num_ct_blocks - 1
    correction_indices = [0, 4]
    assert(len(correction_indices) == 2)

    ad_blocks, ct_blocks = gcm(key1, key2, nonce, tag,
        correction_indices,
        num_ct_blocks, ct_blocks,
        num_ad_blocks, ad_blocks)

# Check that we can decrypt this with a third-party GCM implementation with both keys:
    try:
        additional_data = b''.join(ad_blocks)
        ciphertext = b''.join(ct_blocks)
        cipher = AES.new(key1, AES.MODE_GCM, nonce=nonce)
        _ = cipher.update(additional_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        cipher = AES.new(key2, AES.MODE_GCM, nonce=nonce)
        _ = cipher.update(additional_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # Everything looks good
        print(f'Key1: {hexlify(key1)}')
        print(f'Key2: {hexlify(key2)}')
        print(f'Nonce: {hexlify(nonce)}')
        print(f'AdditionalData: {hexlify(additional_data)}')
        print(f'Ciphertext: {hexlify(ciphertext)}')
        print(f'Tag: {hexlify(tag)}')
    except:
        print('ERROR: Could not decrypt ciphertext.')
