# Test for the linear_cryptanalysis.py module

# Important : to do these tests, go to the root directory (the one containing src)
# then execute in the console "python3 -m src.tests.test_linear_cryptanalysis_gift".

import math
import random
import numpy as np
import gurobipy as gp
from gurobipy import GRB

import linear_cryptanalysis as lc
import tools as tools
import gift_cipher as gift
from gift_cipher import std_bit_perm, std_rev_box_S, std_rev_bit_perm, add_round_constant
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


# converts the S-box from the format in gift_cipher.py into a list of integers

gift_sbox_int = [0] * 16
for inp, out in gift.standard_box_S_conversion:
    x = int("".join(map(str, inp)), 2)
    y = int("".join(map(str, out)), 2)
    gift_sbox_int[x] = y

LAT = compute_lat(gift_sbox_int)
print_lat(LAT)
best_lat_entries(LAT, 10)


# ── Trail search ───────────────────────────────────────────────────────────────

def get_sbox_output_masks(alpha: int, LAT: list) -> list:
    """
    Given a 4-bit input mask for one S-box,
    returns all output masks beta where LAT[alpha][beta] != 0
    meaning there's a linear relation.
    If the nibble is inactive (mask = 0), returns [(0, 16)] (no biais cost)
    """
    if alpha == 0:
        return [(0, 16)]
    return [(beta, LAT[alpha][beta])
            for beta in range(16)
            if LAT[alpha][beta] != 0]


def is_valid_output_mask(mask_64: list) -> bool:
    """
    Returns True if all active bits are at positions 4k or 4k+1 within their nibble.
    Only those positions are touched by AddRoundKey in GIFT-64.
    If beta touches other positions,
    the dot product beta.X won't be affected by the key guess at all,
    which makes the attack impossible.
    """
    for i in range(64):
        if mask_64[i] == 1 and i % 4 >= 2:
            return False
    return True


def find_all_valid_trails(n_rounds: int, LAT: list, beam_width: int = 10000) -> list:
    """
    Search to find the highest-bias trail across n_rounds rounds.
    Keeps only the top candidates by bias at each round.
    """
    
    # builds starting masks

    candidates = []  # (current_mask_tuple, bias_so_far, initial_mask_tuple)
    for nibble in range(16):
        for input_mask in range(1, 16):
            initial = [0] * 64
            for bit in range(3, -1, -1):
                initial[nibble * 4 + (3 - bit)] = (input_mask >> bit) & 1
            t = tuple(initial)
            candidates.append((t, 0.0, t))

    for round_num in range(n_rounds):
        next_candidates = []
        for current_mask_tuple, bias_so_far, initial_mask_tuple in candidates:
            current_mask = list(current_mask_tuple)

            # extract nibbles
            nibbles = []
            for i in range(16):
                nibble_int = 0
                for bit in range(4):
                    nibble_int = (nibble_int << 1) | current_mask[i*4 + bit]
                nibbles.append(nibble_int)

            # For each nibble independently pick the best output mask
            # but try all options for active nibbles one at a time
            nibble_options = [get_sbox_output_masks(n, LAT) for n in nibbles]

            # Only branch on the single most-active nibble, greedy on the rest
            # Find the nibble with the most options (most active)
            best_per_nibble = [max(opts, key=lambda x: abs(x[1])) for opts in nibble_options]

            for branch_nibble in range(16):
                if nibbles[branch_nibble] == 0:
                    continue  # inactive
                for (out_nibble, lat_val) in nibble_options[branch_nibble]:
                    round_bias = 0.0
                    after_sbox_64 = []
                    for i, (base_out, base_lat) in enumerate(best_per_nibble):
                        if i == branch_nibble:
                            chosen_out, chosen_lat = out_nibble, lat_val
                        else:
                            chosen_out, chosen_lat = base_out, base_lat
                        for bit in range(3, -1, -1):
                            after_sbox_64.append((chosen_out >> bit) & 1)
                        if chosen_lat != 16:
                            round_bias += math.log2(abs(chosen_lat) / 16)

                    after_perm_64 = [0] * 64
                    for i in range(64):
                        after_perm_64[63 - std_bit_perm[i]] = after_sbox_64[63 - i]

                    next_candidates.append((
                        tuple(after_perm_64),
                        bias_so_far + round_bias,
                        initial_mask_tuple
                    ))

        # keep best candidates
        next_candidates.sort(key=lambda x: -x[1])
        candidates = next_candidates[:beam_width]
        print(f"  Round {round_num+1}: {len(candidates)} candidates, "
              f"best bias so far: 2^{candidates[0][1]:.2f}")

    valid = [(bias, list(initial), list(final))
             for (final, bias, initial) in candidates
             if is_valid_output_mask(list(final))]
    valid.sort(reverse=True)
    return valid

def find_trail_milp(n_rounds: int, LAT: list) -> list:
    """
    Find the best linear trail over n_rounds using Gurobi MILP.
    Minimizes the number of active S-boxes subject to:
    - Correct mask propagation through PermBits
    - Valid S-box transitions (consistent with LAT)
    - Valid output mask (key-reachable bits only)
    Returns list of (total_log2_bias, initial_mask, final_mask).
    """

    # precomputes valid (input_nibble, output_nibble) pairs from LAT:
    valid_sbox_transitions = []
    for alpha in range(16):
        for beta in range(16):
            if alpha == 0 and beta == 0:
                valid_sbox_transitions.append((alpha, beta))
            elif alpha != 0 and LAT[alpha][beta] != 0:
                valid_sbox_transitions.append((alpha, beta))

    m = gp.Model("gift_linear_trail")
    m.setParam('OutputFlag', 0)


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

            # link activity variable to input nibble
            # a[r][s] must be 1 if any input bit of that S-box is 1, and 0 if all input bits are 0
            for b in range(4):
                m.addConstr(u[r][s*4 + b] <= a[r][s])
            m.addConstr(gp.quicksum(nibble_in) >= a[r][s])

        # PermBits: u[r+1] is v[r] permuted
        # 
        for i in range(64):
            m.addConstr(u[r+1][63 - std_bit_perm[i]] == v[r][63 - i])


    #Solve

    m.optimize()

    if m.status != GRB.OPTIMAL:
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


def partial_decrypt_round(C: list, key: list, active_nibbles: list, round_i: int) -> list:
    """
    Takes a ciphertext and a (guessed) key, and undoes exactly one round:
    Partially decrypt one round of GIFT-64 using the given key.
    Only processes nibbles listed in active_nibbles; other positions are zero.
    """
    # Undo AddRoundConstant
    state = add_round_constant(C[:], round_i)

    # Undo AddRoundKey
    W0 = key[112:128]
    W1 = key[96:112]
    after_key = state[:]
    for j in range(16):
        after_key[63 - (4*j + 1)] ^= W1[15-j]
        after_key[63 - (4*j)]     ^= W0[15-j]

    # Undo PermBits
    after_inv_perm = [0] * 64
    for i in range(64):
        after_inv_perm[63 - std_rev_bit_perm[i]] = after_key[63 - i]

    # Undo SubCells (active nibbles only)
    result = [0] * 64
    for i in range(16):
        if i in active_nibbles:
            nibble = array_to_4_tuple(after_inv_perm[i*4:i*4+4])
            result[i*4:i*4+4] = std_rev_box_S[nibble]

    return result


# ── Attack ─────────────────────────────────────────────────────────────────────

def attack_gift_last_round(pairs, trail, key_true=None, round_i=27):

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

    # Find which key bits actually affect beta.X
    # It runs partial_decrypt_round with a zero key,
    # then flips each of the 128 key bits one at a time
    # and checks whether it changes beta.X.
    # Only the bits that actually matter are added to influential_key_bits.
    # This avoids guessing bits that have no effect

    C_sample = Cs[0].tolist()
    X_base = partial_decrypt_round(C_sample, [0]*128, active_nibbles, round_i=round_i)
    base_dot = sum(X_base[i] * beta[i] for i in range(64)) % 2

    influential_key_bits = []
    for k in range(128):
        kg = [0] * 128
        kg[k] = 1
        X_k = partial_decrypt_round(C_sample, kg, active_nibbles, round_i=round_i)
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
        key_guess = [0] * 128
        for bit_idx, key_pos in enumerate(influential_key_bits):
            key_guess[key_pos] = (candidate_int >> bit_idx) & 1

        Xs = np.array(
            [partial_decrypt_round(C.tolist(), key_guess, active_nibbles, round_i=round_i)
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
    for candidate_int, T0, T1, bias in counts:
        true_partial = sum(K_last[key_pos] << bit_idx
                       for bit_idx, key_pos in enumerate(influential_key_bits))
        if candidate_int == true_partial:
            rank = counts.index((candidate_int, T0, T1, bias)) + 1
            print(f"True key is ranked #{rank} out of {len(counts)}")
            break

    # takes the influencial bits, encodes them the same way as candidate_int,
    # and checks whether the true answer appears in the top ?? candidates.

    if key_true is not None:
        true_partial = sum(key_true[key_pos] << bit_idx
                           for bit_idx, key_pos in enumerate(influential_key_bits))
        top_n = [counts[i][0] for i in range(min(8, len(counts)))]
        bottom_n = [counts[-(i+1)][0] for i in range(min(8, len(counts)))]
        all_candidates = list(set(top_n + bottom_n))
        print(f"  Match (top+bottom 8) aaah still debugging I hate it: {true_partial in all_candidates}")
        print(f"\nTrue key partial bits:")
        print(f"  candidate={true_partial:0{n_bits}b}  (integer {true_partial})")
        print(f"  Top candidate={counts[0][0]:0{n_bits}b}  (integer {counts[0][0]})")

    return counts[0][0], influential_key_bits


# ── Main ───────────────────────────────────────────────────────────────────────

N_ROUNDS = 3
N_PAIRS  = 2**14

valid_trails = find_trail_milp(N_ROUNDS, LAT)

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

KEY = [random.randint(0, 1) for _ in range(128)]

pairs = []
for _ in range(N_PAIRS):
    M = [random.randint(0, 1) for _ in range(64)]
    C = gift.gift_n_round_64(M, KEY, N_ROUNDS + 1)
    pairs.append((M, C))

K_last = KEY[:]
for _ in range(N_ROUNDS):
    K_last = gift.gift_key_schedule_128(K_last)

recovered, influential_bits = attack_gift_last_round(
    pairs, trail, key_true=K_last, round_i=N_ROUNDS
)