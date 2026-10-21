"""
Tests file for gift.

Please don't delete this file.
"""

from launcher import check
import gift_cipher as gc
from tools import int_to_bit_array, ror16, array_to_4_tuple, bit_array_to_int


def apply_sbox(bits):
    result = [None] * 64
    for i in range(0, 64, 4):
        result[i:i+4] = gc.std_box_S[array_to_4_tuple(bits[i:i+4])]
    return result


def apply_permbits(bits):
    result = [None] * 64
    for i in range(64):
        result[63 - gc.std_bit_perm[i]] = bits[63 - i]
    return result


def apply_round_key(bits, key, swap_w=False):
    W0 = key[112:128]
    W1 = key[96:112]
    result = bits[:]
    for j in range(16):
        wa, wb = (W1, W0) if swap_w else (W0, W1)
        result[63 - (4*j + 1)] ^= wa[15-j]
        result[63 - (4*j)]     ^= wb[15-j]
    return result


def apply_full_add_round_key(bits, key, round_i, swap_w=False):
    return gc.add_round_constant(apply_round_key(bits, key, swap_w), round_i)


def apply_inv_add_round_key(bits, key, round_i):
    # inverse secund part of AddRoundKey (it seems to work)
    after_const = gc.add_round_constant(bits, round_i)
    # inverse first part of AddRoundKey
    return apply_round_key(after_const, key, swap_w=True)


tests = []


## gift_key_schedule_128: it works


# List of (input_key,output_key)
tests += [
    ("Key schedule: all zeros",
     lambda: gc.gift_key_schedule_128([0]*128),
     [0]*128),

    ("Key schedule: alternating 0,1",
     lambda: gc.gift_key_schedule_128([0,1]*64),
     [0,1]*64),

    ("Key schedule: repeating 0,0,1",
     lambda: gc.gift_key_schedule_128([0,0,1]*42+[0,0]),
     [1,0,0,0,1,0,0,1,0,0,1,0,0,1,0,0]
     +[1,0,0,1,0,0,1,0,0,1,0,0,0,1,0,0]
     +[0,0,1]*32),
]


## SubCells: it works


# test 1 (calculated by hand))
# test 2 (test vector from [18.1.27])
# test 3 (test vector from [18.3.14])
tests += [
    ("S-Box: all zeros (by hand)",
     lambda: apply_sbox([0]*64),
     [0,0,0,1]*16),

    ("S-Box: test vector [18.1.27]",
     lambda: apply_sbox(int_to_bit_array(0x94ab4b2061f46b9f, 64)),
     int_to_bit_array(0xd6b767413ae637de, 64)),

    ("S-Box: test vector [18.3.14]",
     lambda: apply_sbox(int_to_bit_array(0x7dde03b992afd89b, 64)),
     int_to_bit_array(0x90081c7dd4be02d7, 64)),
]


## PermBits: it works


# test 1 (calculated by hand))
# test 2 (test vector from [18.1.27])
# test 2 (test vector from [18.3.14])
tests += [
    ("PermBits: all zeros input (by hand)",
     lambda: apply_permbits([0,0,0,1]*16),
     [0,0,0,1]*16),

    ("PermBits: test vector [18.1.27]",
     lambda: apply_permbits(int_to_bit_array(0xd6b767413ae637de, 64)),
     int_to_bit_array(0x762bc3ef34f7f524, 64)),

    ("PermBits: test vector [18.3.14]",
     lambda: apply_permbits(int_to_bit_array(0x90081c7dd4be02d7, 64)),
     int_to_bit_array(0x89d304cc1d3687e1, 64)),
]


## AddRoundKey (1/2, without adding round constant): it seems to work


# test 1
# test 2
tests += [
    ("AddRoundKey (key only): all-zero key",
     lambda: apply_round_key([0,0,0,1]*16, [0]*128),
     [0,0,0,1]*16),

    ("AddRoundKey (key only): alternating key",
     lambda: apply_round_key([0,0,0,1]*16, [0,1]*64),
     [0,0,0,1,0,0,1,0]*8),
]


## AddRoundKey (2/2, adding round constant): it seems to work


# test 1
# test 2
tests += [
    ("AddRoundConstant: round 0",
     lambda: gc.add_round_constant([0,0,0,1]*16, 0),
     [1,0,0,1]+[0,0,0,1]*14+[1,0,0,1]),

    ("AddRoundConstant: round 1",
     lambda: gc.add_round_constant([0,0,0,1]*16, 1),
     [1,0,0,1]+[0,0,0,1]*13+[1,0,0,1]*2),
]


## AddRoundKey (total): it works


# test 1 (test vector from [18.1.27])
# test 2 (test vector from [18.3.0])
# test 3 (test vector from [18.3.14])
tests += [
    ("AddRoundKey full: test vector [18.1.27]",
     lambda: apply_full_add_round_key(
         int_to_bit_array(0x762bc3ef34f7f524, 64),
         int_to_bit_array(0x00000000000000000000000000000000, 128),
         27, swap_w=False),
     int_to_bit_array(0xf62bc3ef34f775ac, 64)),

    ("AddRoundKey full: test vector [18.3.0]",
     lambda: apply_full_add_round_key(
         int_to_bit_array(0x75338ddb59f87090, 64),
         int_to_bit_array(0xbd91731eb6bc2713a1f9f6ffc75044e7, 128),
         0, swap_w=True),
     int_to_bit_array(0xd6338ef94aea7189, 64)),

    ("AddRoundKey full: test vector [18.3.14]",
     lambda: apply_full_add_round_key(
         int_to_bit_array(0x89d304cc1d3687e1, 64),
         int_to_bit_array(0xf9a1f6ff50c744e746f6e731f2da3271, 128),
         14, swap_w=True),
     int_to_bit_array(0x2be004fc3ea5af48, 64)),
]


## gift_one_round_64: it works


# test 1
# list of (input,key,round,output) calculated by hand
tests += [
    ("Global cipher: all zeros by hand",
     lambda: gc.gift_one_round_64([0]*64, [0]*128, 0),
     [1,0,0,1]+[0,0,0,1]*14+[1,0,0,1]),
]

# test 2
# list of (input,key,round,output) from [18]
# test vector 1: [18.1.0]
# test vector 2: [18.1.27]
# test vector 3: [18.3.14]
tests += [
    (f"Global cipher: test vector [{r}]",
     lambda p=pt, k=key, r=r: gc.gift_one_round_64(
         int_to_bit_array(p, 64), int_to_bit_array(k, 128), r),
     int_to_bit_array(ct, 64))
    for pt, key, r, ct in [
        (0x0000000000000000, 0x00000000000000000000000000000000,  0, 0x9111111111111119),
        (0x94ab4b2061f46b9f, 0x00000000000000000000000000000000, 27, 0xf62bc3ef34f775ac),
        (0x7dde03b992afd89b, 0xf9a1f6ff50c744e746f6e731f2da3271, 14, 0x2be004fc3ea5af48),
    ]
]


## gift_n_round_64 & gift_cipher: it works


# list of (plaintext, key, ciphertext) in hexadecimal
# These three are the official test vectors [18] of the GitHub repository of GIFT.
_encrypt_vectors = [
    (0x0000000000000000, 0x00000000000000000000000000000000, 0xf62bc3ef34f775ac),
    (0xfedcba9876543210, 0xfedcba9876543210fedcba9876543210, 0xc1b71f66160ff587),
    (0xc450c7727a9b8a7d, 0xbd91731eb6bc2713a1f9f6ffc75044e7, 0xe3272885fa94ba8b),
]

tests += [
    (f"GIFT n-round encrypt: {pt:#x}",
     lambda p=pt, k=key: gc.gift_n_round_64(
         int_to_bit_array(p, 64), int_to_bit_array(k, 128), 28),
     int_to_bit_array(ct, 64))
    for pt, key, ct in _encrypt_vectors
]

tests += [
    (f"GIFT cipher encrypt: {pt:#x}",
     lambda p=pt, k=key: gc.gift_cipher(
         int_to_bit_array(p, 64), int_to_bit_array(k, 128)),
     int_to_bit_array(ct, 64))
    for pt, key, ct in _encrypt_vectors
]


## inverse AddRoundKey: it works


# test (test vector from [18.3.27])
tests += [
    ("Inverse AddRoundKey: test vector [18.3.27]",
     lambda: apply_inv_add_round_key(
         int_to_bit_array(0xe3272885fa94ba8b, 64),
         int_to_bit_array(0xdaf2327187e6ff6f1d43744ed91b1e73, 128),
         27),
     int_to_bit_array(0x41241997fb871a30, 64)),
]


## inverse PermBits: no needs for tests, gift_decrypt_one_round works


## inverse SubCells: no needs for tests, gift_decrypt_one_round works


## gift_decrypt_one_round: it works


# list of (input,key,round,output) from [18]
# test vector 1: [18.1.0]
# test vector 2: [18.1.27]
# test vector 3: [18.3.27]
tests += [
    (f"Decrypt one round: test vector [{r}]",
     lambda ct=ct, k=key, r=r: gc.gift_decrypt_one_round(
         int_to_bit_array(ct, 64), int_to_bit_array(k, 128), r),
     int_to_bit_array(pt, 64))
    for ct, key, r, pt in [
        (0x9111111111111119, 0x00000000000000000000000000000000,  0, 0x0000000000000000),
        (0xf62bc3ef34f775ac, 0x00000000000000000000000000000000, 27, 0x94ab4b2061f46b9f),
        (0xe3272885fa94ba8b, 0xdaf2327187e6ff6f1d43744ed91b1e73, 27, 0xc72677a8da10b024),
    ]
]


## gift_decrypt_n_round & gift_decrypt: it works


# test 1: official test vectors [18] from the GitHub repository of GIFT

# list of (plaintext, key, ciphertext) in hexadecimal
tests += [
    (f"GIFT n-round decrypt: {ct:#x}",
     lambda p=pt, k=key, c=ct: gc.gift_decrypt_n_round(
         int_to_bit_array(c, 64), int_to_bit_array(k, 128), 28),
     int_to_bit_array(pt, 64))
    for pt, key, ct in _encrypt_vectors
]

tests += [
    (f"GIFT decrypt: {ct:#x}",
     lambda p=pt, k=key, c=ct: gc.gift_decrypt(
         int_to_bit_array(c, 64), int_to_bit_array(k, 128)),
     int_to_bit_array(pt, 64))
    for pt, key, ct in _encrypt_vectors
]

# test 2: arbitrary bijectivity tests

# list of (plaintext, key) in hexadecimal
tests += [
    (f"GIFT encrypt and decrypt: {pt:#x}",
     lambda p=pt, k=key: gc.gift_decrypt(
         gc.gift_cipher(int_to_bit_array(p, 64), int_to_bit_array(k, 128)),
         int_to_bit_array(k, 128)),
     int_to_bit_array(pt, 64))
    for pt, key in [
        (0x0123456789abcdef, 0x0123456789abcdef0123456789abcdef),
        (0xadcefb7150936284, 0x753861942951843627aedfcb85207419),
        (0xae789df456cb1230, 0xaedcfb74185209630cb123df456ae789),
    ]
]


for label, fn, expected in tests:
    check(label, fn, expected)

import launcher
print(f"\n{launcher.errors} error(s) found.")