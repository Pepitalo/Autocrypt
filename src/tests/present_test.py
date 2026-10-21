"""
Tests file for PRESENT. Please do not delete this file.
"""


import present_cipher_64_bit as pc
from tools import int_to_bit_array
from launcher import check


## present_key_schedule_80: it works


# test 1
round = 0
key = [1,0]*40
new_key = [0]*4+[0,1]*38

check("Key Schedule PRESENT 80 1",pc.present_key_schedule_80(key,round),new_key)

# test 2
round = 1
key = [1,0]*40
new_key = [0]*4+[0,1]*38
new_key[79-15] = 1

check("Key Schedule PRESENT 80 2",pc.present_key_schedule_80(key,round),new_key)


# test 3
round = 31
key = [0,1]+[0,0,1]*26
new_key = [1,1,1,0] + [0,0,1] * 5 + [0,1,0] *20  + [0]
new_key[79-19] = 1
new_key[79-18] = 1
new_key[79-17] = 0
new_key[79-16] = 1
new_key[79-15] = 1

check("Key Schedule PRESENT 80 3",pc.present_key_schedule_80(key,round),new_key)


## present_one_round: it works


# test 1
input = [0]*64
key = [0]*80
output = [1]*32+[0]*32  # calculated by hand

check(f"PRESENT One Round key {key}",pc.present_one_round(input,key),output)


# test 2
input = [0]*64
key = [1]*80
output = [0]*32+[1]*16+[0]*16   # calculated by hand

check(f"PRESENT One Round key {key}",pc.present_one_round(input,key),output)

# test 3
input = [0,1]*32
key = [0]*32+[1]*32+[0]*16
output = ([0]*8+[1]*8)*4    # calculated by hand

check(f"PRESENT One Round key {key}",pc.present_one_round(input,key),output)


## present_cipher & present_n_round: it works


test_vectors = [(0x0000000000000000,0x00000000000000000000,0x5579C1387B228445),
                (0x0000000000000000,0xFFFFFFFFFFFFFFFFFFFF,0xE72C46C0F5945049),
                (0xFFFFFFFFFFFFFFFF,0x00000000000000000000,0xA112FFC72F68417B),
                (0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFFFFFF,0x3333DCD3213210D2)
                ]   # list of (plaintext, key, ciphertext) in hexadecimal

bit_array_test_vectors = []
for i in range(len(test_vectors)):
    bit_array_test_vectors.append((
    int_to_bit_array(test_vectors[i][0],64),
    int_to_bit_array(test_vectors[i][1],80),
    int_to_bit_array(test_vectors[i][2],64)))

for test_vector in bit_array_test_vectors:
    check(f"PRESENT N Round vector {test_vector}",pc.present_n_round(test_vector[0],test_vector[1],31),test_vector[2])
    check(f"PRESENT Cipher vector {test_vector}",pc.present_cipher(test_vector[0],test_vector[1]),test_vector[2])


## present_decrypt_one_round: it works


# test 1
input = [0]*64
key = [0]*80
output = [1]*32+[0]*32  # calculated by hand

check(f"PRESENT Decrypt one round key {key}",pc.present_decrypt_one_round(output,key),input)


# test 2
input = [0]*64
key = [1]*80
output = [0]*32+[1]*16+[0]*16   # calculated by hand

check(f"PRESENT Decrypt one round key {key}",pc.present_decrypt_one_round(output,key),input)

# test 3
input = [0,1]*32
key = [0]*32+[1]*32+[0]*16
output = ([0]*8+[1]*8)*4    # calculated by hand

check(f"PRESENT Decrypt one round key {key}",pc.present_decrypt_one_round(output,key),input)

# test 4

input = 0x0123456789abcdef
input = int_to_bit_array(input,64)
key = 0x2357bd16180398871212
key = int_to_bit_array(key,80)

check(f"PRESENT Decrypt one round key {key}",pc.present_decrypt_one_round(pc.present_one_round(input,key),key),input)


## present_decrypt & present_decrypt_n_round: it works


# test 1

test_vectors = [(0x0000000000000000,0x00000000000000000000,0x5579C1387B228445),
                (0x0000000000000000,0xFFFFFFFFFFFFFFFFFFFF,0xE72C46C0F5945049),
                (0xFFFFFFFFFFFFFFFF,0x00000000000000000000,0xA112FFC72F68417B),
                (0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFFFFFF,0x3333DCD3213210D2)
                ]   # list of (plaintext, key, ciphertext) in hexadecimal

bit_array_test_vectors = []
for i in range(len(test_vectors)):
    bit_array_test_vectors.append((
    int_to_bit_array(test_vectors[i][0],64),
    int_to_bit_array(test_vectors[i][1],80),
    int_to_bit_array(test_vectors[i][2],64)))

for test_vector in bit_array_test_vectors:
    check(f"PRESENT Decrypt N round vector {test_vector}",pc.present_decrypt_n_round(test_vector[2],test_vector[1],31),test_vector[0])
    check(f"PRESENT Decrypt vector {test_vector}",pc.present_decrypt(test_vector[2],test_vector[1]),test_vector[0])

# test 2

input = 0x0123456789abcdef
input = int_to_bit_array(input,64)
key = 0x2357bd16180398871212
key = int_to_bit_array(key,80)

check(f"PRESENT Decrypt key {key}",pc.present_decrypt(pc.present_cipher(input,key),key),input)
check(f"PRESENT Decrypt key {key}",pc.present_cipher(pc.present_decrypt(input,key),key),input)


## std_bit_perm & std_rev_bit_perm: it works


for key in pc.std_bit_perm.keys():
    check("Perm bit check",pc.std_rev_bit_perm[pc.std_bit_perm[key]],key)

