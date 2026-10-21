"""
Tests file for Alzette.

It seems to work but we don't have any test vectors.
It works at least for c=0x0.
"""


from alzette_cipher import *


## Trivial test: it works


x = [0]*32
y = [0]*32
c = [0]*32
out = [0]*32


assert(alzette_one_round_encryption(x,y,c)==(out,out))


## Test with c=c0: it compiles


alzette_one_round_encryption(x,y)


## Bijectivity test: it works

# Test 1:

x = [0]*32
y = [0]*32
c = [0]*32

x_out, y_out = alzette_one_round_encryption(x, y, c)
x_rev, y_rev = alzette_one_round_decryption(x_out, y_out, c)

assert((x,y)==(x_rev,y_rev))

# Test 2:

x = [0,1]*16
y = [0,0,1]*10+[0,0]

x_out, y_out = alzette_one_round_encryption(x, y)
x_rev, y_rev = alzette_one_round_decryption(x_out, y_out)

assert((x,y)==(x_rev,y_rev))


# without any test vector, it seems hard to go further