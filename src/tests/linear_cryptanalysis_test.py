# Test for the linear_cryptanalysis.py module

# Important : to do these tests, go to the root directory (the one containing src)
# then execute in the console "python3 -m src.tests.test_linear_cryptanalysis".

import linear_cryptanalysis as lc
import tools as tools

print("No real test yet")
print("These tests mainly check that the code runs and that the toy attack behaves as expected.")


## returns 0000, 0001, ... , 1111
def all_4bit_plaintexts() -> list[list[int]]:
    return [tools.int_to_bit_array(x, 4) for x in range(16)]


def attack_last_round_keys(n: int, decrypt, alpha: list[int], beta: list[int], pairs: list[tuple[list[int], list[int]]], round: int = -1) -> list[list[int]]:
    return lc.matsui2_keys(n, decrypt, alpha, beta, pairs)


## recovers best key using matsui 2
## apply decrypt to every ciphertext using that key
## (inspect intermediate states)

def attack_and_partial_decrypt(n: int, decrypt, alpha: list[int], beta: list[int], pairs: list[tuple[list[int], list[int]]], rounds: int = -1) -> list[tuple]:
    best_keys = lc.matsui2_keys(n, decrypt, alpha, beta, pairs)
    results = []
    partial_decryptions = []

    for best_key in best_keys:
        for (M, C) in pairs:
            Cbis = decrypt(C, best_key, round)
            partial_decryptions.append((M, C, Cbis))
        results.append((best_key, partial_descriptions))

    return results


## finds alpha & beta such that alpha.M = beta.S(M) has a strong bias over all 16 inputs.

def find_good_linear_masks(S):
    best = None
    best_bias = -1

    for a in range(1, 16):
        alpha = tools.int_to_bit_array(a, 4)
        for b in range(1, 16):
            beta = tools.int_to_bit_array(b, 4)

            T0 = 0
            T1 = 0

            for x in range(16):
                M = tools.int_to_bit_array(x, 4)
                Y = S[tuple(M)]

                if tools.dot_bit_arrays(alpha, M) == tools.dot_bit_arrays(beta, Y):
                    T0 += 1
                else:
                    T1 += 1

            bias = abs(T0 - T1)
            if bias > best_bias:
                best_bias = bias
                best = (alpha, beta, T0, T1)

    return best


print("-- matsui1 useless test --")

## just a test to see if the function runs smoothly, no actual results

n = 8
alpha = [1,0,1,0,0,0,0,0]
beta  = [0,0,0,0,0,1,0,1]
kappa = [0,0,0,0,0,0,0,0]

pairs = [
    ([0,0,0,0,1,1,1,1], [1,1,1,1,1,1,1,1]),
    ([1,0,1,0,1,0,1,0], [1,1,0,0,1,1,0,0]),
    ([1,1,1,1,0,0,0,0], [0,1,1,0,1,1,0,1]),
    ([0,1,1,1,0,1,1,1], [0,1,1,1,1,0,1,1]),
]

T0, T1 = lc.matsui1(n, alpha, beta, kappa, pairs)
print("T0 =", T0, "T1 =", T1)
print("T0 + T1 =", T0 + T1)


print("-- matsui2 useless test --")

## same, used to see if the function runs smoothly

n = 4
alpha = [1,0,0,0]
beta  = [0,0,0,1]

pairs = [
    ([0,0,0,0], [1,0,0,1]),
    ([1,0,0,0], [0,1,1,0]),
]

def random_decrypt_function(C: list[int], K: list[int], round:int=-1) -> list[int]:
    return tools.xor_two_arrays(C, K)

results = lc.matsui2(n, random_decrypt_function, alpha, beta, pairs)

print("number of key candidates:", len(results))
for (K, T0, T1) in results[:5]:
    print(K, T0, T1)


print("\n-- toy S-box Matsui 2 attack test --")

alpha, beta, approx_T0, approx_T1 = find_good_linear_masks(toy_box_S)

print("\n approximations")
print("chosen alpha:", alpha)
print("chosen beta :", beta)
print("approximation bias on S-box:", approx_T0, approx_T1, "|T0-T1| =", abs(approx_T0 - approx_T1))

real_key = [1, 0, 1, 1]

plaintexts = all_4bit_plaintexts()
pairs = make_pairs(plaintexts, real_key)

## tries each guessed key K_guess, partially decrypts each ciphertext (C' = C XOR Kguess)
## tests wheter alpha.M = beta.C'
## counst how often it holds & picks the key with the best score
recovered_keys = attack_last_round_keys(4, decrypt_toy, alpha, beta, pairs)

print("real key:", real_key)

# Show ranking of key candidates
scores = lc.matsui2(4, decrypt_toy, alpha, beta, pairs)
scores_sorted = sorted(scores, key=lambda x: x[1] - x[2], reverse=True)

print("\nTop candidates:")
for K, T0, T1 in scores_sorted[:10]:
    print(K, "  T0 =", T0, "  T1 =", T1, "  T0-T1 =", T0 - T1, "  |T0-T1| =", abs(T0 - T1))



def test_candidates_against_sbox(candidates, pairs, decrypt, S):

    print("\n-- checking best key candidates against S(M) --")

    for K in candidates:
        all_ok = True

        for M, C in pairs:
            Cbis = decrypt(C, K)
            expected = S[tuple(M)]

            if Cbis != expected:
                all_ok = False
                break

        print("candidate key:", K, "correct partial decryption:", all_ok)

print("\n-- testing top candidates for C' = S(M) --")

scores = lc.matsui2(4, decrypt_toy, alpha, beta, pairs)
scores_sorted = sorted(scores, key=lambda x: x[1] - x[2], reverse=True)

best_candidates = [K for (K, T0, T1) in scores_sorted[:10]]

test_candidates_against_sbox(best_candidates, pairs, decrypt_toy, toy_box_S)