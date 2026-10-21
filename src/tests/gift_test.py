"""
Tests file for gift.

Please don't delete this file.
"""

from launcher import check
import gift_cipher as gc
from tools import int_to_bit_array, ror16, array_to_4_tuple, bit_array_to_int


## gift_key_schedule_128: it works


# List of (input_key,output_key)
test_keys = [([0]*128,[0]*128),
             ([0,1]*64,[0,1]*64),
             ([0,0,1]*42+[0,0],[1,0,0,0,1,0,0,1,0,0,1,0,0,1,0,0]+[1,0,0,1,0,0,1,0,0,1,0,0,0,1,0,0]+[0,0,1]*32)
             ]

for (input,output) in test_keys:
    check(f"Testing key schedule on {input}",gc.gift_key_schedule_128(input),output)


## SubCells: it works


# test 1 (calculated by hand))

bit_array = [0] * 64

box_S_step_array = [None] * 64
for i in range(0, 64, 4):
    box_S_step_array[i:i+4] = gc.std_box_S[array_to_4_tuple(bit_array[i:i+4])]

check(f"S box on {box_S_step_array}",box_S_step_array,[0,0,0,1]*16)

# test 2 (test vector from [18.1.27])

bit_array = int_to_bit_array(0x94ab4b2061f46b9f,64)
output = int_to_bit_array(0xd6b767413ae637de,64)

box_S_step_array = [None] * 64
for i in range(0, 64, 4):
    box_S_step_array[i:i+4] = gc.std_box_S[array_to_4_tuple(bit_array[i:i+4])]

check(f"S box on {box_S_step_array}",box_S_step_array,output)

# test 3 (test vector from [18.3.14])

bit_array = int_to_bit_array(0x7dde03b992afd89b,64)
output = int_to_bit_array(0x90081c7dd4be02d7,64)

box_S_step_array = [None] * 64
for i in range(0, 64, 4):
    box_S_step_array[i:i+4] = gc.std_box_S[array_to_4_tuple(bit_array[i:i+4])]

check(f"S box on {box_S_step_array}",box_S_step_array,output)


## PermBits: it works


# test 1 (calculated by hand))

box_S_step_array=[0,0,0,1]*16

perm_array = [None] * 64
for i in range(64):
    perm_array[63-gc.std_bit_perm[i]] = box_S_step_array[63-i]

check(f"PermBits on {perm_array}",perm_array,[0,0,0,1]*16)

# test 2 (test vector from [18.1.27])

box_S_step_array = int_to_bit_array(0xd6b767413ae637de,64)
output = int_to_bit_array(0x762bc3ef34f7f524,64)

perm_array = [None] * 64
for i in range(64):
    perm_array[63-gc.std_bit_perm[i]] = box_S_step_array[63-i]

check(f"PermBits on {perm_array}",perm_array,output)

# test 2 (test vector from [18.3.14])

box_S_step_array = int_to_bit_array(0x90081c7dd4be02d7,64)
output = int_to_bit_array(0x89d304cc1d3687e1,64)

perm_array = [None] * 64
for i in range(64):
    perm_array[63-gc.std_bit_perm[i]] = box_S_step_array[63-i]

check(f"PermBits on {perm_array}",perm_array,output)


## AddRoundKey (1/2, without adding round constant): it seems to work


# test 1

key = [0] * 128

perm_array = [0,0,0,1]*16

W0 = key[112:128]
W1 = key[96:112]

result = perm_array[:]
for j in range(16):
    result[63 - (4*j + 1)] ^= W0[15-j]
    result[63 - (4*j)]  ^= W1[15-j]

check(f"AddRoundKey on {perm_array[:]}",result,[0,0,0,1]*16)

# test 2

key = [0,1]*64

perm_array = [0,0,0,1]*16

W0 = key[112:128]
W1 = key[96:112]

result = perm_array[:]
for j in range(16):
    result[63 - (4*j + 1)] ^= W0[15-j]
    result[63 - (4*j)]  ^= W1[15-j]

check(f"AddRoundKey on {perm_array[:]}",result,[0,0,0,1,0,0,1,0]*8)


## AddRoundKey (2/2, adding round constant): it seems to work


# test 1

round_i = 0     # i takes values in [0,27]

result = [0,0,0,1]*16

result = gc.add_round_constant(result, round_i)

check(f"AddRoundConstant on {perm_array[:]}",result,[1,0,0,1]+[0,0,0,1]*14+[1,0,0,1])

# test 2

round_i = 1

result = [0,0,0,1]*16

result = gc.add_round_constant(result, round_i)

check(f"AddRoundConstant on {perm_array[:]}",result,[1,0,0,1]+[0,0,0,1]*13+[1,0,0,1]*2)


## AddRoundKey (total): it works


# test 1 (test vector from [18.1.27])

key = int_to_bit_array(0x00000000000000000000000000000000,128)
round_i = 27
perm_array = int_to_bit_array(0x762bc3ef34f7f524,64)
output = int_to_bit_array(0xf62bc3ef34f775ac,64)

W0 = key[112:128]
W1 = key[96:112]

result = perm_array[:]
for j in range(16):
    result[63 - (4*j + 1)] ^= W0[15-j]  # bits have a different order than arrays
    result[63 - (4*j)]  ^= W1[15-j]

result = gc.add_round_constant(result, round_i)

check(f"Checking one round on {perm_array[:]}",result,output)

# test 2 (test vector from [18.3.0])

key = int_to_bit_array(0xbd91731eb6bc2713a1f9f6ffc75044e7,128)
round_i = 0
perm_array = int_to_bit_array(0x75338ddb59f87090,64)
output = int_to_bit_array(0xd6338ef94aea7189,64)

W0 = key[112:128]
W1 = key[96:112]

result = perm_array[:]
for j in range(16):
    result[63 - (4*j + 1)] ^= W1[15-j]  # bits have a different order than arrays
    result[63 - (4*j)]  ^= W0[15-j]

result = gc.add_round_constant(result, round_i)

check(f"Checking one round on {perm_array[:]}",result,output)

# test 3 (test vector from [18.3.14])

key = int_to_bit_array(0xf9a1f6ff50c744e746f6e731f2da3271,128)
round_i = 14
perm_array = int_to_bit_array(0x89d304cc1d3687e1,64)
output = int_to_bit_array(0x2be004fc3ea5af48,64)

W0 = key[112:128]
W1 = key[96:112]

result = perm_array[:]
for j in range(16):
    result[63 - (4*j + 1)] ^= W1[15-j]  # bits have a different order than arrays
    result[63 - (4*j)]  ^= W0[15-j]

result = gc.add_round_constant(result, round_i)

check(f"One round on {perm_array[:]}",result,output)


## gift_one_round_64: it works


# test 1

tmp = [0]*64
for i in [1,5,9,13,17,21,25,29,33,37,41,45,49,53,57,61]:
    tmp[i] = 1

# list of (input,key,round,output) calculated by hand
test_vectors = [([0]*64,[0]*128,0,[1,0,0,1]+[0,0,0,1]*14+[1,0,0,1])
                ]

for (input,key,round,output) in test_vectors:
    check(f"Global cipher on {input} with key {key} on round {round}",gc.gift_one_round_64(input,key,round),output)

# test 2

# list of (input,key,round,output) from [18]
test_vectors = [(0x0000000000000000,
                 0x00000000000000000000000000000000,
                 0,
                 0x9111111111111119),
                (0x94ab4b2061f46b9f,
                 0x00000000000000000000000000000000,
                 27,
                 0xf62bc3ef34f775ac),
                (0x7dde03b992afd89b,
                 0xf9a1f6ff50c744e746f6e731f2da3271,
                 14,
                 0x2be004fc3ea5af48)
                ]
# test vector 1: [18.1.0]
# test vector 2: [18.1.27]
# test vector 3: [18.3.14]

bit_array_test_vectors = []
for i in range(len(test_vectors)):
    bit_array_test_vectors.append((
    int_to_bit_array(test_vectors[i][0],64),
    int_to_bit_array(test_vectors[i][1],128),
    test_vectors[i][2],
    int_to_bit_array(test_vectors[i][3],64)))

for (input,key,round,output) in bit_array_test_vectors:
    check(f"Global cipher on {input} with key {key} on round {round}",gc.gift_one_round_64(input,key,round),output)


## gift_n_round_64 & gift_cipher: it works


# list of (plaintext, key, ciphertext) in hexadecimal
test_vectors = [(0x0000000000000000,
                 0x00000000000000000000000000000000,
                 0xf62bc3ef34f775ac),
                (0xfedcba9876543210,
                 0xfedcba9876543210fedcba9876543210,
                 0xc1b71f66160ff587),
                (0xc450c7727a9b8a7d,
                 0xbd91731eb6bc2713a1f9f6ffc75044e7,
                 0xe3272885fa94ba8b)
                ]
# These three are the official test vectors [18] of the GitHub repository of GIFT.

bit_array_test_vectors = []
for i in range(len(test_vectors)):
    bit_array_test_vectors.append((
    int_to_bit_array(test_vectors[i][0],64),
    int_to_bit_array(test_vectors[i][1],128),
    int_to_bit_array(test_vectors[i][2],64)))

for test_vector in bit_array_test_vectors:
   check(f"GIFT global on {test_vector}",gc.gift_n_round_64(test_vector[0],test_vector[1],28),test_vector[2])
   check(f"GIFT global on {test_vector}",gc.gift_cipher(test_vector[0],test_vector[1]),test_vector[2])


## inverse AddRoundKey: it works


# test (test vector from [18.3.27])
bit_array = int_to_bit_array(0xe3272885fa94ba8b,64)
key = int_to_bit_array(0xdaf2327187e6ff6f1d43744ed91b1e73,128)
round_i = 27
output = int_to_bit_array(0x41241997fb871a30,64)

# inverse secund part of AddRoundKey (it seems to work)
round_constant_added_array = gc.add_round_constant(bit_array,round_i)

# inverse first part of AddRoundKey
W0 = key[112:128]
W1 = key[96:112]
round_key_added_array = round_constant_added_array[:]
for j in range(16):
    round_key_added_array[63 - (4*j + 1)] ^= W1[15-j]
    round_key_added_array[63 - (4*j)] ^= W0[15-j]

check(f"Inverse add round key on {round_key_added_array}",round_key_added_array,output)


## inverse PermBits: no needs for tests, gift_decrypt_one_round works


## inverse SubCells: no needs for tests, gift_decrypt_one_round works


## gift_decrypt_one_round: it works


# list of (input,key,round,output) from [18]
test_vectors = [(0x9111111111111119,
                 0x00000000000000000000000000000000,
                 0,
                 0x0000000000000000),#
                (0xf62bc3ef34f775ac,
                 0x00000000000000000000000000000000,
                 27,
                 0x94ab4b2061f46b9f),
                (0xe3272885fa94ba8b,
                 0xdaf2327187e6ff6f1d43744ed91b1e73,
                 27,
                 0xc72677a8da10b024)#
                ]
# test vector 1: [18.1.0]
# test vector 2: [18.1.27]
# test vector 3: [18.3.27]

bit_array_test_vectors = []
for i in range(len(test_vectors)):
    bit_array_test_vectors.append((
    int_to_bit_array(test_vectors[i][0],64),
    int_to_bit_array(test_vectors[i][1],128),
    test_vectors[i][2],
    int_to_bit_array(test_vectors[i][3],64)))

for (input,key,round,output) in bit_array_test_vectors:
    check(f"Decrypt one round on {input} for key {key} on round {round}",gc.gift_decrypt_one_round(input,key,round),output)


## gift_decrypt_n_round & gift_decrypt: it works


# test 1: official test vectors [18] from the GitHub repository of GIFT

# list of (plaintext, key, ciphertext) in hexadecimal
test_vectors = [(0x0000000000000000,
                 0x00000000000000000000000000000000,
                 0xf62bc3ef34f775ac),
                (0xfedcba9876543210,
                 0xfedcba9876543210fedcba9876543210,
                 0xc1b71f66160ff587),
                (0xc450c7727a9b8a7d,
                 0xbd91731eb6bc2713a1f9f6ffc75044e7,
                 0xe3272885fa94ba8b)
                ]

bit_array_test_vectors = []
for i in range(len(test_vectors)):
    bit_array_test_vectors.append((
    int_to_bit_array(test_vectors[i][0],64),
    int_to_bit_array(test_vectors[i][1],128),
    int_to_bit_array(test_vectors[i][2],64)))

for test_vector in bit_array_test_vectors:
   check(f"GIFT decrypt n round on {test_vector}",gc.gift_decrypt_n_round(test_vector[2],test_vector[1],28),test_vector[0])
   check(f"GIFT decrypt on {test_vector}",gc.gift_decrypt(test_vector[2],test_vector[1]),test_vector[0])

# test 2: arbitrary bijectivity tests

# list of (plaintext, key) in hexadecimal
test_vectors = [(0x0123456789abcdef,
                 0x0123456789abcdef0123456789abcdef),
                (0xadcefb7150936284,
                 0x753861942951843627aedfcb85207419),
                (0xae789df456cb1230,
                 0xaedcfb74185209630cb123df456ae789)
                ]

bit_array_test_vectors = []
for i in range(len(test_vectors)):
    bit_array_test_vectors.append((
    int_to_bit_array(test_vectors[i][0],64),
    int_to_bit_array(test_vectors[i][1],128),))

for (text,key) in bit_array_test_vectors:
   check(f"GIFT encrypt and decrypt on {text} for key {key}",gc.gift_decrypt(gc.gift_cipher(text,key),key),text)
