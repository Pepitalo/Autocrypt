# Test for the differential_cryptanalysis.py module

# Important : to do these tests, go to the root directory (the one containing src)
# then execute in the console with the launcher.

import differential_cryptanalysis as dc
import tools as tools
import numpy as np
import gift_cipher

print("WIP")

present_box_S_conversion = [
    # Since all data manipulation are made on bit it is easier to do so too for the S boxs
    # (Even if the standard presentation of box S is in hexadecimal)
    # The convention used is big endian
    ([0,0,0,0],[1,1,0,0]), # 0 -> C = 12
    ([0,0,0,1],[0,1,0,1]), # 1 -> 5
    ([0,0,1,0],[0,1,1,0]), # 2 -> 6
    ([0,0,1,1],[1,0,1,1]), # 3 -> B = 11
    ([0,1,0,0],[1,0,0,1]), # 4 -> 9
    ([0,1,0,1],[0,0,0,0]), # 5 -> 0
    ([0,1,1,0],[1,0,1,0]), # 6 -> A = 10
    ([0,1,1,1],[1,1,0,1]), # 7 -> D = 13
    ([1,0,0,0],[0,0,1,1]), # 8 -> 3
    ([1,0,0,1],[1,1,1,0]), # 9 -> E = 14
    ([1,0,1,0],[1,1,1,1]), # A -> F = 15
    ([1,0,1,1],[1,0,0,0]), # B -> 8
    ([1,1,0,0],[0,1,0,0]), # C -> 4
    ([1,1,0,1],[0,1,1,1]), # D -> 7
    ([1,1,1,0],[0,0,0,1]), # E -> 1
    ([1,1,1,1],[0,0,1,0]) # F -> 2
]

gift_box_S_conversion = [
    # Since all data manipulation are made on bit it is easier to do so too for the S boxs
    # (Even if the standard presentation of box S is in hexadecimal)
    # The convention used is big endian
    ([0,0,0,0],[0,0,0,1]), # 0 -> 1
    ([0,0,0,1],[1,0,1,0]), # 1 -> A = 10
    ([0,0,1,0],[0,1,0,0]), # 2 -> 4
    ([0,0,1,1],[1,1,0,0]), # 3 -> C= 12
    ([0,1,0,0],[0,1,1,0]), # 4 -> 6
    ([0,1,0,1],[1,1,1,1]), # 5 -> F = 15
    ([0,1,1,0],[0,0,1,1]), # 6 -> 3
    ([0,1,1,1],[1,0,0,1]), # 7 -> 9
    ([1,0,0,0],[0,0,1,0]), # 8 -> 2
    ([1,0,0,1],[1,1,0,1]), # 9 -> D = 13
    ([1,0,1,0],[1,0,1,1]), # A -> B = 11
    ([1,0,1,1],[0,1,1,1]), # B -> 7
    ([1,1,0,0],[0,1,0,1]), # C -> 5
    ([1,1,0,1],[0,0,0,0]), # D -> 0
    ([1,1,1,0],[1,0,0,0]), # E -> 8
    ([1,1,1,1],[1,1,1,0]) # F -> E = 14
]

toy_box_S_conversion = [
    # Since all data manipulation are made on bit it is easier to do so too for the S boxs
    # (Even if the standard presentation of box S is in hexadecimal)
    # The convention used is big endian
    ([0,0,0,0],[0,0,1,0]), # 0 -> 2
    ([0,0,0,1],[0,0,0,0]), # 1 -> 0
    ([0,0,1,0],[0,1,0,0]), # 2 -> 4
    ([0,0,1,1],[0,0,1,1]), # 3 -> 3
    ([0,1,0,0],[1,0,0,1]), # 4 -> 9
    ([0,1,0,1],[0,1,0,1]), # 5 -> 5
    ([0,1,1,0],[0,1,1,0]), # 6 -> 6
    ([0,1,1,1],[0,1,1,1]), # 7 -> 7
    ([1,0,0,0],[0,0,0,1]), # 8 -> 1
    ([1,0,0,1],[1,1,0,1]), # 9 -> D = 13
    ([1,0,1,0],[1,1,1,0]), # A -> E = 14
    ([1,0,1,1],[1,1,1,1]), # B -> F = 15
    ([1,1,0,0],[1,0,1,0]), # C -> A = 10
    ([1,1,0,1],[1,0,0,0]), # D -> 8
    ([1,1,1,0],[1,1,0,0]), # E -> C = 12
    ([1,1,1,1],[1,0,1,1]) # F -> B = 11
]

present_box_S = {} # The standard S box used to encrypt the message with present
present_rev_box_S = {} # The reverse S box used to decrypt the message with present
gift_box_S = {} # The standard S box used to encrypt the message with gift
gift_rev_box_S = {} # The reverse S box used to decrypt the message with gift
toy_box_S = {} # The standard S box used to encrypt the message
toy_rev_box_S = {} # The reverse S box used to decrypt the message

for (a,b) in present_box_S_conversion:
    present_box_S[tools.array_to_4_tuple(a)] = b
    present_rev_box_S[tools.array_to_4_tuple(b)] = a

for (a,b) in gift_box_S_conversion:
    gift_box_S[tools.array_to_4_tuple(a)] = b
    gift_rev_box_S[tools.array_to_4_tuple(b)] = a

for (a,b) in toy_box_S_conversion:
    toy_box_S[tools.array_to_4_tuple(a)] = b
    toy_rev_box_S[tools.array_to_4_tuple(b)] = a

toy_bit_perm = {0:0, 1:2, 2:6, 3:8, 4:1, 5:7, 6:9, 7:12, 8:4, 9:3, 10:10, 11:14, 12:5, 13:11, 14:13, 15:15}


present_box_S_DDT = dc.DDT(present_box_S,4)
gift_box_S_DDT = dc.DDT(gift_box_S,4)
toy_box_S_DDT = dc.DDT(toy_box_S,4)

print("-- PRESENT --")

for i in range(16):
    print(present_box_S_DDT[i])

print("-- GIFT --")

for i in range(16):
    print(gift_box_S_DDT[i])

print("-- TOY --")

for i in range(16):
    print(toy_box_S_DDT[i])


print("\n\nMore example with the gift S Box\n\n")

lst_trans, lst_imp_trans = dc.generate_transition(gift_box_S_DDT)

print("\n\nPossible transition array\n\n")
for i in range(len(lst_trans)):
    print(lst_trans[i])
print(f"There were {len(lst_trans)} possible transition")

print("\n\nImpossible transition array\n\n")
for i in range(len(lst_imp_trans)):
    print(lst_imp_trans[i])
print(f"There were {len(lst_imp_trans)} impossible transition")

ieq_lst = dc.generate_inequalities(lst_trans)

print("\n\nPossible transition inequalities\n\n")
for ieq in ieq_lst[:20]:
    print(ieq)
print(f"There were {len(ieq_lst)} inequalities")

lst_imp_trans2 = lst_imp_trans.copy()
ieq_gha_lst = dc.greedy_convex_hull_2(ieq_lst.copy(), lst_imp_trans.copy())
print("\n\nReduced Possible transition inequalities with the convex hull algorithm\n\n")
for ieq in ieq_gha_lst[:20]:
    print(ieq)
print(f"There were {len(ieq_gha_lst)} inequalities")

ieq_gha_lst2 = dc.merge_imp_trans(lst_imp_trans2, 500)
print("\n\nReduced Impossible transition with the logical modelling\n\n")
for ieq in ieq_gha_lst2[:20]:
    print(dc.blocking_formula(ieq))
print(f"There were {len(ieq_gha_lst2)} inequalities")

print("First tests for milp (with toy s box) :\n\n")
np.set_printoptions(legacy='1.25')

for i in range(1,0):
    print(f"round {i} :")
    res,sbox,bits = dc.milp_minimize_active_s_box(ieq_gha_lst,gift_cipher.std_bit_perm,16,4,i)
    lst_sbox = tools.split_bit_array(sbox.astype(int),16)
    lst_bit = [tools.split_bit_array(bits[64*j:64*(j+1)].astype(int),4) for j in range(i+1)]
    print(f"res {res}")
    for j in range(i+1):
        print(bits[64*j:64*(j+1)])
        print(lst_sbox[j])
        print(("|"+"-"*4+"| ")*16)
    p = dc.trail_probability(gift_box_S_DDT, sbox, bits, gift_cipher.std_bit_perm, 16, 4, i)
    print(p)
    print()

if dc.differential_full_distinguisher_gift_opt(7, 64, tools.generate_bit_array_diff(64,3)[0:1], "test2.txt"):
    print("Success")

temp = tools.generate_bit_array_diff(16,1)
for i in range(len(temp)):
    print(tools.bit_array_to_hex(temp[i]))