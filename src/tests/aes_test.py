"""
Tests file for AES. Execute this file: if no error occures, then all works.
"""

from tools import int_to_bit_array, split_bit_array, bits_number
from aes import *
from launcher import check


### AES Tests


## key_expansion: it works


key = 0x2b7e151628aed2a6abf7158809cf4f3c

key = int_to_bit_array(key,128)

w = 0x2b7e151628aed2a6abf7158809cf4f3ca0fafe1788542cb123a339392a6c7605f2c295f27a96b9435935807a7359f67f3d80477d4716fe3e1e237e446d7a883bef44a541a8525b7fb671253bdb0bad00d4d1c6f87c839d87caf2b8bc11f915bc6d88a37a110b3efddbf98641ca0093fd4e54f70e5f5fc9f384a64fb24ea6dc4fead27321b58dbad2312bf5607f8d292fac7766f319fadc2128d12941575c006ed014f9a8c9ee2589e13f0cc8b6630ca6

w = int_to_bit_array(w,1408)
w = split_bit_array(w,32)
for i in range(len(w)):
    w[i] = split_bit_array(w[i],8)  # here, w is a sequence of words, i.e. a sequence of 4-bytes

w_bis=key_expansion(key)

check("",w_bis,w)


## cipher: it works


input = 0x3243f6a8885a308d313198a2e0370734

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)

output = 0x3925841d02dc09fbdc118597196a0b32

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)

check("",cipher(input,10,w),output)


## inv_cipher: it works


# first test
check("",inv_cipher(output,10,w),input)

# secund test
input = 0x00000000000000000000000000000000

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)

check("",inv_cipher(cipher(input,10,w),10,w),input)
check("",cipher(inv_cipher(input,10,w),10,w),input)

#third test
input = 0x0123456789abcdef1011121314151617

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)

check("",inv_cipher(cipher(input,10,w),10,w),input)
check("",cipher(inv_cipher(input,10,w),10,w),input)


### Intermediate functions for key_expansion


## rot_word: it works


check("",rot_word([[0]*6+[0,0],[0]*6+[0,1],[0]*6+[1,0],[0]*6+[1,1]]),[[0]*6+[0,1],[0]*6+[1,0],[0]*6+[1,1],[0]*6+[0,0]])

# list of (before rot_word, after rot_word) examples in hexadecimal
examples = [(0x09cf4f3c,0xcf4f3c09),(0x2a6c7605,0x6c76052a),(0x7359f67f,0x59f67f73)]

examples_bit_array = []
for example in examples:
    examples_bit_array.append((split_bit_array(int_to_bit_array(example[0],4*8),8),split_bit_array(int_to_bit_array(example[1],4*8),8)))

for example in examples_bit_array:
    check("",rot_word(example[0]),example[1])


## sub_word: it works


# list of (before sub_word, after sub_word) examples in hexadecimal
examples = [(0xcf4f3c09,0x8a84eb01),(0x6c76052a,0x50386be5),(0x59f67f73,0xcb42d28f),(0x7a883b6d,0xdac4e23c),(0x0bad00db,0x2b9563b9),(0xf915bc11,0x99596582),(0x0093fdca,0x63dc5474),(0xa6dc4f4e,0x2486842f),(0x8d292f7f,0x5da515d2),(0x5c006e57,0x4a639f5b)]

examples_bit_array = []
for example in examples:
    examples_bit_array.append((split_bit_array(int_to_bit_array(example[0],4*8),8),split_bit_array(int_to_bit_array(example[1],4*8),8)))

for example in examples_bit_array:
    check("",sub_word(example[0]),example[1])


## s_box: it works


# list of (before s_box, after s_box) examples in hexadecimal
examples = [(0xcf,0x8a),(0x4f,0x84),(0x3c,0xeb),(0x09,0x01),(0x6c,0x50),(0x76,0x38),(0x05,0x6b),(0x2a,0xe5)]

examples_bit_array = []
for example in examples:
    examples_bit_array.append((int_to_bit_array(example[0],8),int_to_bit_array(example[1],8)))

for example in examples_bit_array:
    check("",s_box(example[0]),example[1])


## r_con: it works


examples = [0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000]

examples_bit_array = []
for example in examples:
    examples_bit_array.append(split_bit_array(int_to_bit_array(example,4*8),8))

for i in range(10):
    check("",r_con[i],examples_bit_array[i])


### Intermediate functions for cipher and inv_cipher


## one_round: it works


# first test
input = 0x193de3bea0f4e22b9ac68d2ae9f84808

round_key = w[4:8]

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xa49c7ff2689f352b6b5bea43026a5049

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",one_round(s_input,round_key),s_output)

# secund test
input = 0xa49c7ff2689f352b6b5bea43026a5049

round_key = w[8:12]

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xaa8f5f0361dde3ef82d24ad26832469a

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",one_round(s_input,round_key),s_output)


## add_round_key: it works


# first test
input = 0x3243f6a8885a308d313198a2e0370734

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x193de3bea0f4e22b9ac68d2ae9f84808

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",add_round_key(s_input,w[0:4]),s_output)

# secund test
input = 0x046681e5e0cb199a48f8d37a2806264c

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xa49c7ff2689f352b6b5bea43026a5049

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",add_round_key(s_input,w[4:8]),s_output)

# third test
input = 0x584dcaf11b4b5aacdbe7caa81b6bb0e5

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xaa8f5f0361dde3ef82d24ad26832469a

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",add_round_key(s_input,w[8:12]),s_output)


## sub_bytes: it works


# first test
input = 0x193de3bea0f4e22b9ac68d2ae9f84808

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xd42711aee0bf98f1b8b45de51e415230

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",sub_bytes(s_input),s_output)

# secund test
input = 0xa49c7ff2689f352b6b5bea43026a5049

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x49ded28945db96f17f39871a7702533b

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",sub_bytes(s_input),s_output)

# third test
input = 0xaa8f5f0361dde3ef82d24ad26832469a

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xac73cf7befc111df13b5d6b545235ab8

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",sub_bytes(s_input),s_output)


## inv_sub_bytes: it works


# first test
input = 0x193de3bea0f4e22b9ac68d2ae9f84808

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xd42711aee0bf98f1b8b45de51e415230

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",inv_sub_bytes(s_output),s_input)

# secund test
input = 0xa49c7ff2689f352b6b5bea43026a5049

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x49ded28945db96f17f39871a7702533b

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",inv_sub_bytes(s_output),s_input)

# third test
input = 0xaa8f5f0361dde3ef82d24ad26832469a

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xac73cf7befc111df13b5d6b545235ab8

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",inv_sub_bytes(s_output),s_input)


## shift_rows: it works


# first test
input = 0xd42711aee0bf98f1b8b45de51e415230

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xd4bf5d30e0b452aeb84111f11e2798e5

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",shift_rows(s_input),s_output)

# secund test
input = 0x49ded28945db96f17f39871a7702533b

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x49db873b453953897f02d2f177de961a

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",shift_rows(s_input),s_output)

# third test
input = 0xac73cf7befc111df13b5d6b545235ab8

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xacc1d6b8efb55a7b1323cfdf457311b5

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",shift_rows(s_input),s_output)


## inv_shift_rows: it works


# first test
input = 0xd42711aee0bf98f1b8b45de51e415230

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xd4bf5d30e0b452aeb84111f11e2798e5

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",inv_shift_rows(s_output),s_input)

# secund test
input = 0x49ded28945db96f17f39871a7702533b

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x49db873b453953897f02d2f177de961a

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",inv_shift_rows(s_output),s_input)

# third test
input = 0xac73cf7befc111df13b5d6b545235ab8

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0xacc1d6b8efb55a7b1323cfdf457311b5

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",inv_shift_rows(s_output),s_input)


## mix_columns: it works


# first test
input = 0xd4bf5d30e0b452aeb84111f11e2798e5

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x046681e5e0cb199a48f8d37a2806264c

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",mix_columns(s_input),s_output)

# secund test
input = 0x49db873b453953897f02d2f177de961a

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x584dcaf11b4b5aacdbe7caa81b6bb0e5

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",mix_columns(s_input),s_output)

# third test
input = 0xacc1d6b8efb55a7b1323cfdf457311b5

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x75ec0993200b633353c0cf7cbb25d0dc

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",mix_columns(s_input),s_output)


## inv_mix_columns: it works


# first test
input = 0xd4bf5d30e0b452aeb84111f11e2798e5

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x046681e5e0cb199a48f8d37a2806264c

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",inv_mix_columns(s_output),s_input)

# secund test
input = 0x49db873b453953897f02d2f177de961a

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x584dcaf11b4b5aacdbe7caa81b6bb0e5

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",inv_mix_columns(s_output),s_input)

# third test
input = 0xacc1d6b8efb55a7b1323cfdf457311b5

input = int_to_bit_array(input,128)
input = split_bit_array(input,8)
s_input = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_input[r][c] = input[r+4*c]

output = 0x75ec0993200b633353c0cf7cbb25d0dc

output = int_to_bit_array(output,128)
output = split_bit_array(output,8)
s_output = [[[0]*8 for _ in range(4)] for _ in range(4)]
for r in range(4):
    for c in range(4):
        s_output[r][c] = output[r+4*c]

check("",inv_mix_columns(s_output),s_input)


### Some tools


## bit_matrix_vector_product: it works


M = [[0,0,0,0],
    [0,0,0,0],
    [0,0,0,0],
    [0,0,0,0]]
x = [0,0,0,0]
check("",bit_matrix_vector_product(M,x),[0,0,0,0])
x = [0,0,0,1]
check("",bit_matrix_vector_product(M,x),[0,0,0,0])
x = [1,0,1,0]
check("",bit_matrix_vector_product(M,x),[0,0,0,0])
x = [1,1,1,1]
check("",bit_matrix_vector_product(M,x),[0,0,0,0])

M = [[1,0,0,0],
    [0,1,0,0],
    [0,0,1,0],
    [0,0,0,1]]
x = [0,0,0,0]
check("",bit_matrix_vector_product(M,x),[0,0,0,0])
x = [0,0,0,1]
check("",bit_matrix_vector_product(M,x),[0,0,0,1])
x = [1,0,1,0]
check("",bit_matrix_vector_product(M,x),[1,0,1,0])
x = [1,1,1,1]
check("",bit_matrix_vector_product(M,x),[1,1,1,1])

M = [[1,0,1,0],
    [0,1,0,1],
    [0,1,1,0],
    [1,0,0,1]]
x = [0,0,0,0]
check("",bit_matrix_vector_product(M,x),[0,0,0,0])
x = [0,0,0,1]
check("",bit_matrix_vector_product(M,x),[0,1,0,1])
x = [1,0,1,0]
check("",bit_matrix_vector_product(M,x),[0,0,1,1])
x = [1,1,1,1]
check("",bit_matrix_vector_product(M,x),[0,0,0,0])


## words_matrix_vector_product: no need for a proper test, if mix_columns works, then it works


M = [[[0]*6+[1,0],[0]*6+[1,1],[0]*6+[0,1],[0]*6+[0,1]],
    [[0]*6+[0,1],[0]*6+[1,0],[0]*6+[1,1],[0]*6+[0,1]],
    [[0]*6+[0,1],[0]*6+[0,1],[0]*6+[1,0],[0]*6+[1,1]],
    [[0]*6+[1,1],[0]*6+[0,1],[0]*6+[0,1],[0]*6+[1,0]]]

s = [[0,1,0,1,0,1,0,1],[0,0,1,1,0,0,1,1],[0,0,0,0,1,1,1,1],[0,0,0,0,0,0,0,0]]


## xor_words: it works


check("",xor_words([[0,1,0,1,0,1,0,1],[0,0,1,1,0,0,1,1],[0,0,0,0,1,1,1,1],[0,0,0,0,0,0,0,0]],
                [[1,1,1,1,1,1,1,1],[1,1,1,1,0,0,0,0],[1,1,0,0,1,1,0,0],[1,0,1,0,1,0,1,0]]),
                [[1,0,1,0,1,0,1,0],[1,1,0,0,0,0,1,1],[1,1,0,0,0,0,1,1],[1,0,1,0,1,0,1,0]])

examples = [(0x8a84eb01,0x01000000,0x8b84eb01),(0x50386be5,0x02000000,0x52386be5),(0xcb42d28f,0x04000000,0xcf42d28f)]

examples_bit_array = []
for example in examples:
    examples_bit_array.append((split_bit_array(int_to_bit_array(example[0],4*8),8),split_bit_array(int_to_bit_array(example[1],4*8),8),split_bit_array(int_to_bit_array(example[2],4*8),8)))

for example in examples_bit_array:
    check("",xor_words(example[0],example[1]),example[2])


### Operations on GF(2**8) (i.e. between bytes)


## addition: it works


check("",addition([0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0]),[0,0,0,0,0,0,0,0])
check("",addition([0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,1]),[0,0,0,0,0,0,0,1])
check("",addition([0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0]),[0,0,0,0,0,0,0,1])
check("",addition([0,0,0,0,0,0,0,0],[1,0,1,0,1,0,1,0]),[1,0,1,0,1,0,1,0])
check("",addition([1,0,1,0,1,0,1,0],[0,0,0,0,0,0,0,0]),[1,0,1,0,1,0,1,0])
check("",addition([0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,1]),[0,0,0,0,0,0,0,0])
check("",addition([0,0,0,0,0,0,0,1],[1,0,1,0,1,0,1,0]),[1,0,1,0,1,0,1,1])
check("",addition([1,0,1,0,1,0,1,0],[0,0,0,0,0,0,0,1]),[1,0,1,0,1,0,1,1])
check("",addition([1,0,1,0,1,0,1,0],[0,1,0,1,0,1,0,1]),[1,1,1,1,1,1,1,1])
check("",addition([0,1,0,1,0,1,0,1],[1,0,1,0,1,0,1,0]),[1,1,1,1,1,1,1,1])


## multiplication: it works


check("",multiplication([0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0]),[0,0,0,0,0,0,0,0])
check("",multiplication([0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,1]),[0,0,0,0,0,0,0,0])
check("",multiplication([0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0]),[0,0,0,0,0,0,0,0])
check("",multiplication([0,0,0,0,0,0,0,0],[1,0,1,0,1,0,1,0]),[0,0,0,0,0,0,0,0])
check("",multiplication([1,0,1,0,1,0,1,0],[0,0,0,0,0,0,0,0]),[0,0,0,0,0,0,0,0])
check("",multiplication([0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,1]),[0,0,0,0,0,0,0,1])
check("",multiplication([0,0,0,0,0,0,0,1],[1,0,1,0,1,0,1,0]),[1,0,1,0,1,0,1,0])
check("",multiplication([1,0,1,0,1,0,1,0],[0,0,0,0,0,0,0,1]),[1,0,1,0,1,0,1,0])
check("",multiplication([1,0,1,0,1,0,1,0],[0,1,0,1,0,1,0,1]),[0,1,0,1,1,0,0,1])
check("",multiplication([0,1,0,1,0,1,0,1],[1,0,1,0,1,0,1,0]),[0,1,0,1,1,0,0,1])


## inverse: it works


examples = [[0,0,0,0,0,0,0,1],[0,0,0,0,0,0,1,0],[1,0,0,0,0,0,0,0],[1,0,1,0,1,0,1,0],[0,1,0,1,0,1,0,1]]
for example in examples:
    check("",multiplication(inverse(example),example),[0,0,0,0,0,0,0,1])


## degree: it works


check("",degree([0,0,0,0]),-1)
check("",degree([0,0,0,1]),0)
check("",degree([1,0,1,0]),3)
check("",degree([0,1,0,1]),2)


## euclidian_division: it works


check("",euclidian_division([0]*8+[0,0,0,0,0,0,0,0],[0]*8+[0,0,0,0,0,0,0,1]),[0,0,0,0,0,0,0,0])
check("",euclidian_division([0]*8+[0,0,0,0,0,0,0,0],[0]*8+[1,0,1,0,1,0,1,0]),[0,0,0,0,0,0,0,0])
check("",euclidian_division([0]*8+[0,0,0,0,0,0,0,1],[0]*8+[0,0,0,0,0,0,0,1]),[0,0,0,0,0,0,0,0])
check("",euclidian_division([0]*8+[0,0,0,0,0,0,0,1],[0]*8+[1,0,1,0,1,0,1,0]),[0,0,0,0,0,0,0,1])
check("",euclidian_division([0]*8+[1,0,1,0,1,0,1,0],[0]*8+[0,0,0,0,0,0,0,1]),[0,0,0,0,0,0,0,0])
check("",euclidian_division([0]*8+[1,0,1,0,1,0,1,0],[0]*8+[0,1,0,1,0,1,0,1]),[0,0,0,0,0,0,0,0])
check("",euclidian_division([0]*8+[0,1,0,1,0,1,0,1],[0]*8+[1,0,1,0,1,0,1,0]),[0,1,0,1,0,1,0,1])

