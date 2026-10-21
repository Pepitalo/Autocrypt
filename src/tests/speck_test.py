"""Tests file for 'speck_cipher.py'."""


from tools import int_to_bit_array
from speck_cipher import *
from launcher import check


# (block_size, key_size, key, plaintext, ciphertext)
test_vectors = [(32, 64, 0x1918111009080100, 0x6574694c, 0xa86842f2),
                (48, 72, 0x1211100a0908020100, 0x20796c6c6172, 0xc049a5385adc),
                (48, 96, 0x1a19181211100a0908020100, 0x6d2073696874, 0x735e10b6445d),
                (64, 96, 0x131211100b0a090803020100, 0x74614620736e6165, 0x9f7952ec4175946c),
                (64, 128, 0x1b1a1918131211100b0a090803020100, 0x3b7265747475432d, 0x8c6fa548454e028b),
                (96, 96, 0x0d0c0b0a0908050403020100, 0x65776f68202c656761737520, 0x9e4d09ab717862bdde8f79aa),
                (96, 144, 0x1514131211100d0c0b0a0908050403020100, 0x656d6974206e69202c726576, 0x2bf31072228a7ae440252ee6),
                (128, 128, 0x0f0e0d0c0b0a09080706050403020100, 0x6c617669757165207469206564616d20, 0xa65d9851797832657860fedf5c570d18),
                (128, 192, 0x17161514131211100f0e0d0c0b0a09080706050403020100, 0x726148206665696843206f7420746e65, 0x1be4cf3a13135566f9bc185de03c1886),
                (128, 256, 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100, 0x65736f6874206e49202e72656e6f6f70, 0x4109010405c0f53e4eeeb48d9c188f43)]


bit_array_test_vectors = []
for block_size, key_size, key, plaintext, ciphertext in test_vectors:
    bit_array_key, bit_array_plaintext, bit_array_ciphertext = int_to_bit_array(key,key_size), int_to_bit_array(plaintext), int_to_bit_array(ciphertext)
    bit_array_test_vectors.append((block_size, key_size, bit_array_key, bit_array_plaintext, bit_array_ciphertext))


## Tests on some of the tools
# Only some are tested, when necessary. The others aren't tested because they already seem to work.
# NB. I let the 'assert' for the tools because we don't really need a 'check' in this case.


# xor: it seems to work

x = [0,0,0,0,1,1,1,1]
y = [0,1,0,1,0,1,0,1]
z = [0,1,0,1,1,0,1,0]

assert(xor(x,y)==z)


# addition: it seems to work

x = [1,1,1,1,1,1,1,1]
y = [0,0,0,0,0,0,0,0]
z = [1,1,1,1,1,1,1,1]

assert(addition(8,x,y)==z)

x = [1,1,1,1,1,1,1,1]
y = [0,0,0,0,0,0,0,1]
z = [0,0,0,0,0,0,0,0]

assert(addition(8,x,y)==z)

x = [1,1,1,1,1,1,1,1]
y = [1,1,1,1,1,1,1,1]
z = [1,1,1,1,1,1,1,0]

assert(addition(8,x,y)==z)


# substraction: it seems to work

x = [1,1,1,1,1,1,1,1]
y = [0,0,0,0,0,0,0,0]
z = [1,1,1,1,1,1,1,1]

assert(substraction(8,x,y)==z)

x = [1,1,1,1,1,1,1,1]
y = [0,0,0,0,0,0,0,1]
z = [1,1,1,1,1,1,1,0]

assert(substraction(8,x,y)==z)

x = [1,1,1,1,1,1,1,1]
y = [1,1,1,1,1,1,1,1]
z = [0,0,0,0,0,0,0,0]

assert(substraction(8,x,y)==z)

x = [0,0,0,0,0,0,0,0]
y = [1,1,1,1,1,1,1,1]
z = [0,0,0,0,0,0,0,1]

assert(substraction(8,x,y)==z)


## speck & inverse_speck (and indirectly all intermediate functions): it all works

for block_size, key_size, key, plaintext, ciphertext in bit_array_test_vectors:

    n = block_size // 2
    m = key_size // n
    x_in, y_in = plaintext[0:n], plaintext[n:2*n]
    x_out, y_out = ciphertext[0:n], ciphertext[n:2*n]
    l = []
    for i in range(m-1):
        l.append(key[(m-2-i)*n:(m-1-i)*n])
    k = [key[(m-1)*n:m*n]]

    check(f"Speck{block_size}/{key_size=}", speck(n, m, x_in, y_in, l, k), (x_out, y_out))
    check(f"invSpeck{block_size}/{key_size=}", inverse_speck(n, m, x_out, y_out, l, k), (x_in, y_in))


## Do the bit perm and S-box dicts compile ?


# As I expected, it is too complex to compile.


#SPECK_S_BOX = SPECK_S_BOX_n(16)
#print(SPECK_S_BOX)


## Do the functions before computing these dicts work ? Yes.


assert(speck_s_box(16,tuple([0]*32))==tuple([0]*32))








