from Crypto.Cipher import AES
import struct

load('gcm_siv_impl.sage')

# Construct a ciphertext which is valid for two keys
key1 = unhexlify('01'*16)
key2 = unhexlify('02'*16)
nonce = unhexlify('03'*12)
tag = unhexlify('04'*16)

key1_auth, key1_enc = derive_keys(key1, nonce)
key2_auth, key2_enc = derive_keys(key2, nonce)

# Recover output of POLYVAL. As the output of POLYVAL is masked before it is encrypted
# to obtain the tag in GCM-SIV, we have to retry different tag values to ensure we can
# get a valid tag.
while(1):
    T1_tmp = recover_POLYVAL(key1_enc, tag, nonce + unhexlify('00'*4))
    T2_tmp = recover_POLYVAL(key2_enc, tag, nonce + unhexlify('00'*4))
    if T1_tmp and T2_tmp:
        break
    tag = inc(tag)

T1 = byte_array_to_field_element_gcm_siv(T1_tmp)
T2 = byte_array_to_field_element_gcm_siv(T2_tmp)

# Define the messages to be encrypted. Note that some of these values are
# overwritten.
num_blocks = 6
m1 = [b'\xaa'*16 for _ in range(num_blocks)]
m2 = [b'\xbb'*16 for _ in range(num_blocks)]
M1 = [byte_array_to_field_element_gcm_siv(block) for block in m1]
M2 = [byte_array_to_field_element_gcm_siv(block) for block in m2]

# In order to get a matching ciphertext, we will at each bit position either
# control the bit in m1 or m2. For simplicity of this implementation this
# is only done on a 16-byte block level.
#
# Additionally we require 2 blocks to correct the tag, therefore we need two
# indices which overlap between m1 and m2.
controlled_m1 = [0, 1, 2, 3]
controlled_m2 = [0, 1, 4, 5]
assert(len(controlled_m1) + len(controlled_m2) == num_blocks + 2)

# We also need to compute the keystream in advance to enforce equal
# ciphertexts between the two messages. For this we just encrypt an all 0
# message.
all_zero_msg = zero_block * num_blocks
counter_block = tag[:15] + bytes([tag[15] | 0x80])

s1 = AES_CTR(key1_enc, counter_block, all_zero_msg)
s2 = AES_CTR(key2_enc, counter_block, all_zero_msg)

S1 = [byte_array_to_field_element_gcm_siv(s1[i*16:i*16+16]) for i in range(len(s1) // 16)]
S2 = [byte_array_to_field_element_gcm_siv(s2[i*16:i*16+16]) for i in range(len(s2) // 16)]

# Length block without using AD
LEN = byte_array_to_field_element_gcm_siv(unhexlify('00'*8) + struct.pack(b'<Q', num_blocks * 128))

# Constants for POLYVAL
xinv128 = F(x^127 + x^124 + x^121 + x^114 + 1)
H1 = byte_array_to_field_element_gcm_siv(key1_auth) * xinv128
H2 = byte_array_to_field_element_gcm_siv(key2_auth) * xinv128

# Construct the system of linear equations
#
# We need two linear equations to guarantee the correct value
# after recovering POLYVAL and additional num_blocks equation
# to ensure the ciphertexts are equal.
sum_h1 = sum([H1^(num_blocks + 1 - i) * M1[i] for i in range(num_blocks) if i not in controlled_m1])
sum_h2 = sum([H2^(num_blocks + 1 - i) * M2[i] for i in range(num_blocks) if i not in controlled_m2])

b = []

# Fix T1
b.append(LEN*H1 + T1 + sum_h1)
# Fix T2
b.append(LEN*H2 + T2 + sum_h2)

# Add conditions for equal ciphertext
for i in range(num_blocks):
    tmp_condition = S1[i] + S2[i]
    if i not in controlled_m1:
        tmp_condition += M1[i]
    if i not in controlled_m2:
        tmp_condition += M2[i]
    b.append(tmp_condition)

# Construct matrix
A = []

# Equations for getting correct POLYVAL values
m1_lhs = [H1^(num_blocks - i + 1) for i in controlled_m1]
m2_lhs = [H2^(num_blocks - i + 1) for i in controlled_m2]
A.append(m1_lhs + [0]*len(controlled_m2))
A.append([0]*len(controlled_m1) + m2_lhs)

# Equations for getting equal ciphertexts
for i in range(num_blocks):
    ct_lhs = [0] * (len(controlled_m1) + len(controlled_m2))
    if i in controlled_m1:
        ct_lhs[controlled_m1.index(i)] = 1
    if i in controlled_m2:
        ct_lhs[controlled_m2.index(i) + len(controlled_m1)] = 1
    A.append(ct_lhs)

# Find solution
A = Matrix(F, A)
b = vector(F, b)
solution = A.solve_right(b)

new_M1 = solution[:len(controlled_m1)]
new_M2 = solution[len(controlled_m1):]

for i, v in enumerate(controlled_m1):
    M1[v] = new_M1[i]
for i, v in enumerate(controlled_m2):
    M2[v] = new_M2[i]

m1 = b''.join([field_element_to_byte_array_gcm_siv(M) for M in M1])
m2 = b''.join([field_element_to_byte_array_gcm_siv(M) for M in M2])

ciphertext1, tag1 = AES_GCM_SIV_encrypt(m1, key1, nonce)
ciphertext2, tag2 = AES_GCM_SIV_encrypt(m2, key2, nonce)

assert(ciphertext1 == ciphertext2)
assert(tag1 == tag2)

print(f'Key1: {hexlify(key1)}')
print(f'Key2: {hexlify(key2)}')
print(f'Nonce: {hexlify(nonce)}')
print(f'Ciphertext: {hexlify(ciphertext1)}')
print(f'Tag: {hexlify(tag1)}')
