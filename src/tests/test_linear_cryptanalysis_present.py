# Test for the linear_cryptanalysis.py module — PRESENT version

# Important : to do these tests, go to the root directory (the one containing src)
# then execute in the console "python3 -m src.tests.test_linear_cryptanalysis_present".

import math
import random
import numpy as np
import gurobipy as gp
from gurobipy import GRB

import linear_cryptanalysis as lc
import tools as tools
import present_cipher_64_bit as present
from present_cipher_64_bit import std_bit_perm as present_perm, std_rev_bit_perm as present_rev_perm, std_rev_box_S as present_rev_sbox
from tools import array_to_4_tuple


# ── LAT ───────────────────────────────────────────────────────────────────────

def parity(x: int) -> int:
    """
    Takes an integer, XORs all its bits together, returns 0 or 1.
    """
    p = 0
    while x:
        p ^= (x & 1)        # x&1 extracts the least significant bit of x. ^= XORs it to p.
        x >>= 1             # >> shifts x one bit to the right
    return p


def compute_lat(S):
    """
    Takes the S-box as a list of 16 values.
    For every input mask alpha (0–15) and output mask beta (0–15),
    it loops over all 16 possible inputs x,
    computes parity(alpha & x) and parity(beta & S(x)),
    and adds +1 if they match or −1 if they don't.
    The result at LAT[alpha][beta] is a number between −16 and +16.
    Zero means perfectly balanced.
    Anything nonzero is a bias.
    """

    size = 16
    LAT = [[0] * size for _ in range(size)]
    for alpha in range(size):
        for beta in range(size):
            total = 0
            for x in range(size):
                y = S[x]
                if parity(alpha & x) == parity(beta & y):
                    total += 1
                else:
                    total -= 1
            LAT[alpha][beta] = total
    return LAT


def print_lat(lat):
    print("\n========== LAT ==========\n")
    print("     ", end="")
    
    for beta in range(16):
        beta_hex = hex(beta).upper().replace("0X", "")
        print("   " + beta_hex, end="")
    print()

    for alpha in range(16):
        alpha_hex = hex(alpha).upper().replace("0X", "")
        print("   " + alpha_hex + " ", end="")

        for beta in range(16):
            value = lat[alpha][beta]

            value_str = str(value)
            padding = " " * (4 - len(value_str))
            print(padding + value_str, end="")

        print()


def best_lat_entries(lat, top_n=10):
    entries = []
    for alpha in range(1, 16):
        for beta in range(1, 16):
            bias = abs(lat[alpha][beta])
            entries.append((bias, alpha, beta, lat[alpha][beta]))
    entries.sort(reverse=True)
    print("\n========== BEST APPROXIMATIONS ==========\n")
    for i in range(top_n):
        bias, alpha, beta, value = entries[i]
        
        rank_str = str(i + 1)
        if len(rank_str) < 2:
            rank_str = " " + rank_str

        alpha_bin = bin(alpha).replace("0b", "")
        while len(alpha_bin) < 4:
            alpha_bin = "0" + alpha_bin

        beta_bin = bin(beta).replace("0b", "")
        while len(beta_bin) < 4:
            beta_bin = "0" + beta_bin

        value_str = str(value)
        while len(value_str) < 3:
            value_str = " " + value_str

        print(rank_str + ". " + "alpha=" + alpha_bin + "   " + "beta=" + beta_bin + "   " + "LAT=" + value_str + "   " + "|LAT|=" + str(bias))



# converts the S-box from the format in present_cipher.py into a list of integers

present_sbox_int = [0] * 16
for inp, out in present.standard_box_S_conversion:
    x = int("".join(map(str, inp)), 2)
    y = int("".join(map(str, out)), 2)
    present_sbox_int[x] = y

LAT = compute_lat(present_sbox_int)
print_lat(LAT)
best_lat_entries(LAT, 10)


# ── Trail search ───────────────────────────────────────────────────────────────

def find_trail_milp_present(n_rounds: int, LAT: list) -> list:
    """
    Find the best linear trail over n_rounds using Gurobi MILP for PRESENT.
    Minimizes the number of active S-boxes.
    """
    # precomputes valid (input_nibble, output_nibble) pairs from LAT:
    valid_sbox_transitions = []
    for alpha in range(16):
        for beta in range(16):
            if alpha == 0 and beta == 0:
                valid_sbox_transitions.append((alpha, beta))
            elif alpha != 0 and LAT[alpha][beta] != 0:
                valid_sbox_transitions.append((alpha, beta))

    m = gp.Model("present_linear_trail")
    m.setParam('OutputFlag', 0)
    m.setParam('TimeLimit', 300)
    m.setParam('MIPGap', 0.0)


    # Variaaaaaaaaaaables

    # u[r][i] = bit i of the mask at round boundary r
    # r=0 is the input mask, r=1 is the mask after round 1, .... r=n_rounds is the output mask
    u = [[m.addVar(vtype=GRB.BINARY, name=f"u_{r}_{i}")
          for i in range(64)]
         for r in range(n_rounds + 1)]
    
    # a[r][s] = 1 if S-box s is active at round r ("a" means "active")

    a = [[m.addVar(vtype=GRB.BINARY, name=f"a_{r}_{s}")
          for s in range(16)]
         for r in range(n_rounds)]

    # v[r][i] = bit i of the mask after SubCells at round r (between SubCells and PermBits)
    v = [[m.addVar(vtype=GRB.BINARY, name=f"v_{r}_{i}")
          for i in range(64)]
         for r in range(n_rounds)]

    # t[r][s][(alpha,beta)] = 1 if S-box s at round r uses transition (alpha,beta)
    # (so that we know which path through the S-box the trail takes)
    t = {}
    for r in range(n_rounds):
        for s in range(16):
            for (alpha, beta) in valid_sbox_transitions:
                t[r, s, alpha, beta] = m.addVar(
                    vtype=GRB.BINARY,
                    name=f"t_{r}_{s}_{alpha}_{beta}"
                )

    m.update()


    # minimize total active S-boxes
    m.setObjective(
        gp.quicksum(a[r][s] for r in range(n_rounds) for s in range(16)),
        GRB.MINIMIZE
    )


    # COOOOOONSTRAINTS yayy

    # at least one bit must be active in the input mask
    m.addConstr(gp.quicksum(u[0][i] for i in range(64)) >= 1)

    for r in range(n_rounds):
        for s in range(16):
            nibble_in = [u[r][s*4 + b] for b in range(4)]

            # exactly one transition per S-box, tel harry potter qui est l'élu
            m.addConstr(
                gp.quicksum(t[r, s, alpha, beta]
                            for (alpha, beta) in valid_sbox_transitions) == 1
            )

            # link transition variable to input bits
            # (the input mask bits of S-box s must match the alpha of the chosen transition t)
            for b in range(4):
                m.addConstr(
                    u[r][s*4 + b] == gp.quicksum(
                        ((alpha >> (3 - b)) & 1) * t[r, s, alpha, beta]
                        for (alpha, beta) in valid_sbox_transitions
                    )
                )

            # Link transition variable to output bits
            # v[r] must match the beta of the chosen transition
            for b in range(4):
                m.addConstr(
                    v[r][s*4 + b] == gp.quicksum(
                        ((beta >> (3 - b)) & 1) * t[r, s, alpha, beta]
                        for (alpha, beta) in valid_sbox_transitions
                    )
                )

            for b in range(4):
                m.addConstr(u[r][s*4 + b] <= a[r][s])
            m.addConstr(gp.quicksum(nibble_in) >= a[r][s])

        # PermBits (direct indexing, no reversal like GIFT)
        for i in range(64):
            m.addConstr(u[r+1][present_perm[i]] == v[r][i])

    #Solve

    m.optimize()

    if m.status != GRB.OPTIMAL and m.status != GRB.TIME_LIMIT:
        print(f"Gurobi status: {m.status}")
        return []
    
    #extract solution
    initial_mask = [int(round(u[0][i].X)) for i in range(64)]
    final_mask   = [int(round(u[n_rounds][i].X)) for i in range(64)]
    n_active     = int(round(m.objVal))

    # each active S-box contributes at best log2(8/16) = -1 to the bias
    total_log2_bias = n_active * math.log2(8 / 16)

    print(f"Gurobi found trail with {n_active} active S-boxes")
    print(f"  Estimated bias: 2^{total_log2_bias:.2f}")
    print(f"  Input mask active bits:  {[i for i,b in enumerate(initial_mask) if b]}")
    print(f"  Output mask active bits: {[i for i,b in enumerate(final_mask) if b]}")

    return [(total_log2_bias, initial_mask, final_mask)]


# ── Partial decryption ─────────────────────────────────────────────────────────

def get_active_nibble_indices(mask_64: list) -> list:
    """
    Rturns the indices (0–15) of nibbles that have at least one active bit in a mask.
    These are the nibbles the attack needs to focus on.
    """
    return [i for i in range(16) if any(mask_64[i*4:i*4+4])]


def partial_decrypt_present(C: list, key: list, active_nibbles: list) -> list:
    """
    Undoes one round of PRESENT.
    PRESENT round order: AddRoundKey -> SubCells -> PermBits
    Inverse order:       inv PermBits -> inv SubCells -> AddRoundKey
    key is 80 bits.
    """
    # Undo PermBits
    after_inv_perm = [0] * 64
    for i in range(64):
        after_inv_perm[present_rev_perm[i]] = C[i]

    # Undo SubCells (active nibbles only)
    after_inv_sbox = [0] * 64
    for i in range(16):
        if i in active_nibbles:
            nibble = array_to_4_tuple(after_inv_perm[i*4:i*4+4])
            after_inv_sbox[i*4:i*4+4] = present_rev_sbox[nibble]

    # Undo AddRoundKey
    result = after_inv_sbox[:]
    for i in range(64):
        result[63-i] = after_inv_sbox[63-i] ^ key[79-(16+i)]

    return result


# ── Attack ─────────────────────────────────────────────────────────────────────

def attack_present_last_round(pairs, trail, key_true=None):

    ## pulls alpha (plaintext mask) and beta (intermediate state mask) from the trail
    ## and finds the active nibbles of beta
    alpha = trail['masks'][0]
    beta  = trail['masks'][-1]
    active_nibbles = get_active_nibble_indices(beta)

    ## for all plaintext-ciphertext pairs at once,
    ## computes A = parity(alpha.M) for every plaintext M
    alpha_np = np.array(alpha, dtype=np.uint8)
    beta_np  = np.array(beta,  dtype=np.uint8)

    Ms = np.array([M for M, C in pairs], dtype=np.uint8)
    Cs = np.array([C for M, C in pairs], dtype=np.uint8)
    A  = (Ms @ alpha_np) % 2

    # find which key bits actually affect beta.X
    C_sample = Cs[0].tolist()
    X_base = partial_decrypt_present(C_sample, [0]*80, active_nibbles)
    base_dot = sum(X_base[i] * beta[i] for i in range(64)) % 2

    influential_key_bits = []
    for k in range(80):
        kg = [0] * 80
        kg[k] = 1
        X_k = partial_decrypt_present(C_sample, kg, active_nibbles)
        if sum(X_k[i] * beta[i] for i in range(64)) % 2 != base_dot:
            influential_key_bits.append(k)

    print(f"Key bits that affect beta·X: {influential_key_bits}")
    n_candidates = 2 ** len(influential_key_bits)
    print(f"Enumerating {n_candidates} candidates")

    # For each candidate integer, builds a key guess by unpacking the candidate's bits
    # into exactly the influential positions
    # (all other positions stay zero, since we know they don't matter).
    # Then for every ciphertext it calls partial_decrypt_round to get Xs,
    # stacks all results into a matrix, and computes B = parity(beta.Xs) for each pair
    
    # then it counts T0 (how many pairs have A[i] == B[i] (the linear relation holds)) and T1

    counts = []
    for candidate_int in range(n_candidates):
        key_guess = [0] * 80
        for bit_idx, key_pos in enumerate(influential_key_bits):
            key_guess[key_pos] = (candidate_int >> bit_idx) & 1

        Xs = np.array(
            [partial_decrypt_present(C.tolist(), key_guess, active_nibbles)
             for C in Cs],
            dtype=np.uint8
        )
        B  = (Xs @ beta_np) % 2
        T0 = int(np.sum(A == B))
        T1 = len(pairs) - T0
        counts.append((candidate_int, T0, T1, abs(T0 - T1)))

    counts.sort(key=lambda x: -x[3])

    n_bits = len(influential_key_bits)
    print(f"\nTop 5 key candidates:")
    for candidate_int, T0, T1, bias in counts[:5]:
        print(f"  candidate={candidate_int:0{n_bits}b}  T0={T0}  T1={T1}  |T0-T1|={bias}")


    # takes the influencial bits, encodes them the same way as candidate_int,
    # and checks whether the true answer appears in the top ?? candidates.

    if key_true is not None:
        true_partial = sum(key_true[key_pos] << bit_idx
                           for bit_idx, key_pos in enumerate(influential_key_bits))
        top_n = [counts[i][0] for i in range(min(8, len(counts)))]
        bottom_n = [counts[-(i+1)][0] for i in range(min(8, len(counts)))]
        all_candidates = list(set(top_n + bottom_n))
        for rank, (c, _, _, _) in enumerate(counts):
            if c == true_partial:
                print(f"  True key is ranked #{rank+1} out of {len(counts)}")
                break
        print(f"\nTrue key partial bits:")
        print(f"  candidate={true_partial:0{n_bits}b}  (integer {true_partial})")
        print(f"  Top candidate={counts[0][0]:0{n_bits}b}  (integer {counts[0][0]})")
        print(f"  Match (top+bottom 8): {true_partial in all_candidates}")

    return counts[0][0], influential_key_bits


def present_n_round_no_final_xor(bit_array: list, key: list, n: int) -> list:
    """
    Encrypts for n rounds without the final key XOR.
    Used for linear cryptanalysis where we attack the last round separately.
    """
    bit_array = bit_array[:]
    key = key[:]
    for i in range(1, n + 1):
        bit_array = present.present_one_round(bit_array, key)
        key = present.present_key_schedule_80(key, i)
    return bit_array


# ── Main ───────────────────────────────────────────────────────────────────────

N_ROUNDS = 7
N_PAIRS  = 2**24

valid_trails = find_trail_milp_present(N_ROUNDS, LAT)

if not valid_trails:
    print(f"No valid trail found for {N_ROUNDS} rounds, stopping.")
    exit()

best_bias, best_initial, best_final = valid_trails[0]
trail = {
    'masks': [best_initial, best_final],
    'total_log2_bias': best_bias,
    'n_active_sboxes': sum(1 for i in range(16) if any(best_initial[i*4:i*4+4]))
}
print(f"Best {N_ROUNDS}-round trail found:")
print(f"  Total log2 bias: {best_bias:.3f}  (bias ≈ 2^{best_bias:.2f})")
print(f"  Active S-boxes:  {trail['n_active_sboxes']}")

KEY = [random.randint(0, 1) for _ in range(80)]

pairs = []
for _ in range(N_PAIRS):
    M = [random.randint(0, 1) for _ in range(64)]
    C = present_n_round_no_final_xor(M[:], KEY[:], N_ROUNDS + 1)
    pairs.append((M, C))

# compute the key used in round N_ROUNDS+1
K_last = KEY[:]
for i in range(1, N_ROUNDS + 1):
    K_last = present.present_key_schedule_80(K_last, i)

recovered, influential_bits = attack_present_last_round(
    pairs, trail, key_true=K_last
)