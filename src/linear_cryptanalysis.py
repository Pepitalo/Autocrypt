# This module aims to implement the methods that will be used for linear attacks.

import math
import random
import time
import numpy as np
import gurobipy as gp
from gurobipy import GRB

import tools as tools
import gift_cipher as gift
from gift_cipher import std_bit_perm, std_rev_box_S, std_rev_bit_perm, add_round_constant
from tools import array_to_4_tuple

import present_cipher_64_bit as present
from present_cipher_64_bit import std_bit_perm as present_perm, std_rev_bit_perm as present_rev_perm, std_rev_box_S as present_rev_sbox


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
    print("\n---- Best Approximations ----\n")
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

    valid = [(bias, list(initial), list(final))
             for (final, bias, initial) in candidates
             if is_valid_output_mask(list(final))]
    valid.sort(reverse=True)
    return valid

def find_trail_milp(n_rounds: int, LAT: list, excluded_final_masks: list = None) -> list:
    """
    Find the best linear trail over n_rounds using Gurobi MILP.
    Minimizes the number of active S-boxes subject to:
    - Correct mask propagation through PermBits
    - Valid S-box transitions (consistent with LAT)
    - Valid output mask (key-reachable bits only)
    - (Optionnel) Excludes the final masks to force gurobi to find a new trail (for recursive attacks)
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

    # Exclusion of the previous trails for recursive attacks
    if excluded_final_masks:
        for ex_mask in excluded_final_masks:
            # Forces at least one bit of difference from the previous paths
            diff_expr = gp.quicksum(
                (1 - u[n_rounds][i]) if ex_mask[i] == 1 else u[n_rounds][i]
                for i in range(64)
            )
            m.addConstr(diff_expr >= 1)

    #Solve

    m.optimize()

    if m.status != GRB.OPTIMAL:
        return []

    #extract solution
    initial_mask = [int(round(u[0][i].X)) for i in range(64)]
    final_mask   = [int(round(u[n_rounds][i].X)) for i in range(64)]
    n_active     = int(round(m.objVal))

    # each active S-box contributes at best log2(8/16) = -1 to the bias
    total_log2_bias = n_active * math.log2(8 / 16)

    return [(total_log2_bias, initial_mask, final_mask)]

def find_trail_milp_present(n_rounds: int, LAT: list, excluded_final_masks: list = None) -> list:
    """
    Find the best linear trail over n_rounds using Gurobi MILP for PRESENT.
    Minimizes the number of active S-boxes.
    - (Optional) Excludes the final masks to force gurobi to find a new trail (for recursive attacks)
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

    # Exclusion of the previous trails for recursive attacks
    if excluded_final_masks:
        for ex_mask in excluded_final_masks:
            # Forces at least one bit of difference from the previous paths
            diff_expr = gp.quicksum(
                (1 - u[n_rounds][i]) if ex_mask[i] == 1 else u[n_rounds][i]
                for i in range(64)
            )
            m.addConstr(diff_expr >= 1)

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

    n_candidates = 2 ** len(influential_key_bits)

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

    if key_true is not None:
        # Code d'affichage propre ajouté
        true_key_str = ""
        for b in key_true:
            true_key_str += str(b)
            
        pointer_list = [" "] * 128
        for pos in influential_key_bits:
            pointer_list[pos] = "^"
        pointer_str = "".join(pointer_list)
        
        print("\n======================= VISUAL RECOVERY REPORT =======================")
        print("Real key (128 bits):")
        print(true_key_str)
        print(pointer_str)
        print("           (The ^^^ indicate the recovered bits of the key)")
        print("======================================================================\n")

        true_partial = sum(key_true[key_pos] << bit_idx
                       for bit_idx, key_pos in enumerate(influential_key_bits))
        rank = [x[0] for x in counts].index(true_partial) + 1
        print(f"-> Success : The actual key bits has been found at rank #{rank} / {len(counts)}")

    return counts[0][0], influential_key_bits

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

    n_candidates = 2 ** len(influential_key_bits)

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

    if key_true is not None:
        true_key_str = ""
        for b in key_true:
            true_key_str += str(b)
            
        pointer_list = [" "] * 80
        for pos in influential_key_bits:
            pointer_list[pos] = "^"
        pointer_str = "".join(pointer_list)
        
        print("\n======================= VISUAL RECOVERY REPORT =======================")
        print("Real key (80 bits):")
        print(true_key_str)
        print(pointer_str)
        print("           (The ^^^ indicate the recovered bits of the key)")
        print("======================================================================\n")

        true_partial = sum(key_true[key_pos] << bit_idx
                           for bit_idx, key_pos in enumerate(influential_key_bits))
        rank = [x[0] for x in counts].index(true_partial) + 1
        print(f"-> Success : The actual key bits has been found at rank #{rank} / {len(counts)}")

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



def matsui1(n:int,alpha:list[int],beta:list[int],kappa:list[int],pairs:list[tuple[list[int]]])->tuple[int]:
    """
    Assume we have an approximation alpha . M + beta . C + kappa . K = 0
    with positive bias.
    Assume we have collected enough known plaintext-ciphertext pairs (M_i,C_i).
    Input: alpha, beta, gamma are bit arrays with length n.
        pairs is a list of tuples (Mi,Ci).
        Mi and Ci are bit arrays with length n.
    Output: (T0,T1) numbers of validation and invalidation of the approximation
    """
    assert(n==len(alpha))
    assert(n==len(beta))
    assert(n==len(kappa))
    T0 = T1 = 0
    for (Mi,Ci) in pairs:
        A = tools.xor_reduce(tools.and_arrays([Mi, alpha]))
        B = tools.xor_reduce(tools.and_arrays([Ci, beta]))
        if A == B:
            T0 += 1
        else:
            T1 += 1
    return (T0,T1)


def matsui1_kappa_K(n:int,alpha:list[int],beta:list[int],kappa:list[int],pairs:list[tuple[list[int]]])->int:
    """
    Same assumptions as for matsui1.
    Input: alpha, beta, gamma are bit arrays with length n.
        pairs is a list of tuples (Mi,Ci).
        Mi and Ci are bit arrays with length n.
    Output: the most likely kappa . K where K is the key to be recovered
    """
    T = matsui1(n,alpha,beta,kappa,pairs)
    if T[0] > T[1]:
        return 0
    else:
        return 1


def matsui2(n:int,decrypt,alpha:list[int],beta:list[int],pairs:list[tuple[list[int]]],round:int=-1)->list[tuple]:   #TO-DO: precise the decrypt function
    """
    Same assumptions as for matsui1.
    Input: same as matsui1, without kappa, and with
            decrypt: list[int], list[int], int -> list[int] function
                decrypt(input, key, round) -> input
            round: round index (-1 by default if the round is not neededs)
    Output: a list of (keys, T0, T1) (the difference T0-T1 must be high).
    """

    results = []
    K = [0] * n

    for _ in range(2**n):
        T0 = 0
        T1 = 0

        for Mi, Ci in pairs:
            Cbis = decrypt(Ci, K, round)
            A = tools.xor_reduce(tools.and_arrays([Mi, alpha]))
            B = tools.xor_reduce(tools.and_arrays([Cbis, beta]))
            if A == B:
                T0 += 1
            else:
                T1 += 1

        results.append((K.copy(), T0, T1))
        tools.incr_bit_array(K)

    return results


def matsui2_keys(n:int,decrypt,alpha:list[int],beta:list[int],pairs:list[tuple[list[int]]],round:int=-1)->list[list[int]]:
    """
    Same assumptions as for matsui1.
    Input: same as matsui1, without kappa, and with
            decrypt: list[int], list[int], int -> list[int] function
            round: round index (-1 by default if the round is not neededs)
    Output: the list of most likely keys
    """
    keys = matsui2(n,decrypt,alpha,beta,pairs,round)
    best_difference = 0
    for (K,T0,T1) in keys:
        difference = T0-T1
        if best_difference < difference:
            best_difference = difference
    best_keys = []
    for (K,T0,T1) in keys:
        if T0-T1 == best_difference:
            best_keys.append(K.copy())
    return best_keys

menu = {
    "1": ("Run linear attack on GIFT-64"),
    "2": ("Run linear attack on PRESENT"),
    "3": ("Recursive attack on GIFT-64 (Iterative Key Recovery)"),
    "4": ("Recursive attack on PRESENT (Iterative Key Recovery)"),
    "0": ("Quit ")
}

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        tools.print_menu("Linear Cryptanalysis Application", menu)

        try:
            choice = input("Choice: ").strip()

            if choice not in menu:
                print(f"Invalid choice: {choice}")
                input("Press enter to continue...")
                continue

            if choice == "0":
                print("Closing Linear Cryptanalysis Application.")
                sys.exit(0)

            print("------------------------------- SETUP PHASE -------------------------------")

            print("Computing LAT matrix...")

            if choice in ["1", "3"]:
                gift_sbox_int = [0] * 16
                for inp, out in gift.standard_box_S_conversion:
                    x = int("".join(map(str, inp)), 2)
                    y = int("".join(map(str, out)), 2)
                    gift_sbox_int[x] = y

                LAT = compute_lat(gift_sbox_int)
                if choice == "1":
                    best_lat_entries(LAT, 10)

            elif choice in ["2", "4"]:
                present_sbox_int = [0] * 16
                for inp, out in present.standard_box_S_conversion:
                    x = int("".join(map(str, inp)), 2)
                    y = int("".join(map(str, out)), 2)
                    present_sbox_int[x] = y

                LAT = compute_lat(present_sbox_int)
                print_lat(LAT)
                best_lat_entries(LAT, 10)

            print("------------------------------- Done -------------------------------\n\n")

            raw_n_pairs = input("Number of plaintext-ciphertext pairs: ").strip()
            N_PAIRS = int(eval(raw_n_pairs))
            raw_n = input("Number of rounds: ").strip()
            if not raw_n.isdigit() or int(raw_n) < 1:
                print("Invalid number of rounds.")
                input("Press enter to continue...")
                continue
            N_ROUNDS = int(raw_n)

            print("------------------------------- SETUP PHASE -------------------------------")
            if choice == "1":
                valid_trails = find_trail_milp(N_ROUNDS, LAT)
                if not valid_trails:
                    print(f"No valid trail found for {N_ROUNDS} rounds, stopping.")
                    exit()
                best_bias, best_initial, best_final = valid_trails[0]
                trail = {'masks': [best_initial, best_final], 'total_log2_bias': best_bias}
                print(f"  Total log2 bias: {best_bias:.3f}  (bias ≈ 2^{best_bias:.2f})")

            elif choice == "2":
                valid_trails = find_trail_milp_present(N_ROUNDS, LAT)
                if not valid_trails:
                    print(f"No valid trail found for {N_ROUNDS} rounds, stopping.")
                    exit()
                best_bias, best_initial, best_final = valid_trails[0]
                trail = {'masks': [best_initial, best_final], 'total_log2_bias': best_bias}
                print(f"  Total log2 bias: {best_bias:.3f}  (bias ≈ 2^{best_bias:.2f})")

            print("------------------------------- SETUP DONE -------------------------------\n\n")

            if choice in ["1", "3"]:
                KEY = tools.read_key(32)
            elif choice in ["2", "4"]:
                KEY = tools.read_key(20)
            K_last = KEY[:]

            print("------------------------------- COMPUTATION PHASE -------------------------------\n\n")
            start_total_time = time.time()

            pairs = []
            for _ in range(N_PAIRS):
                M = [random.randint(0, 1) for _ in range(64)]
                if choice in ["1", "3"]:
                    C = gift.gift_n_round_64(M, KEY, N_ROUNDS + 1)
                elif choice in ["2", "4"]:
                    C = present_n_round_no_final_xor(M[:], KEY[:], N_ROUNDS + 1)
                pairs.append((M, C))

            if choice == "1":
                for _ in range(N_ROUNDS):
                    K_last = gift.gift_key_schedule_128(K_last)
                recovered, influential_bits = attack_gift_last_round(
                    pairs, trail, key_true=K_last, round_i=N_ROUNDS)

            elif choice == "2":
                for i in range(1, N_ROUNDS + 1):
                    K_last = present.present_key_schedule_80(K_last, i)
                recovered, influential_bits = attack_present_last_round(
                    pairs, trail, key_true=K_last)

            elif choice == "3":
                for _ in range(N_ROUNDS):
                    K_last = gift.gift_key_schedule_128(K_last)
                
                known_bits_mask = [0] * 128
                excluded_final_masks = []
                iteration = 1
                bits_left = int(input("Acceptable number or remaining unknown bits :"))
                bits_to_find = 128 - bits_left # 88 bits needed for threshold
                
                print(f"--- STARTING RECURSIVE ATTACK ON GIFT-64 ---")
                print(f"Objective : Recover {bits_to_find} bits (Remaining <= 40 bits for quick bruteforce )\n")
                
                while sum(known_bits_mask) < bits_to_find:
                    print(f"\n--- Round {iteration} ---")
                    elapsed_total = time.time() - start_total_time
                    print(f"[Time Elapsed Since Start: {elapsed_total:.2f} seconds]")
                    # Looking for a new trail excluding previous ones
                    valid_trails = find_trail_milp(N_ROUNDS, LAT, excluded_final_masks)
                    if not valid_trails:
                        print("\nWARNING : No more linear paths were found by GUROBI")
                        break
                        
                    best_bias, best_initial, best_final = valid_trails[0]
                    excluded_final_masks.append(best_final)
                    
                    current_trail = {
                        'masks': [best_initial, best_final],
                        'total_log2_bias': best_bias,
                        'n_active_sboxes': sum(1 for i in range(16) if any(best_initial[i*4:i*4+4]))
                    }
                    
                    print(f"New trail found (Bias: {best_bias:.2f}). Attack in progress...")
                    recovered, influential_bits = attack_gift_last_round(
                        pairs, current_trail, key_true=K_last, round_i=N_ROUNDS)
                    
                    # Updates the known bits
                    new_bits_count = 0
                    for pos in influential_bits:
                        if known_bits_mask[pos] == 0:
                            known_bits_mask[pos] = 1
                            new_bits_count += 1
                            
                    if new_bits_count > 0:
                        print("\n======================= GLOBAL RECOVERY REPORT =======================")
                        print(f"Step {iteration} - Known bits of K_last : {sum(known_bits_mask)}/128")
                        global_key_str = "".join(str(K_last[i]) if known_bits_mask[i] else "?" for i in range(128))
                        print(f"\n{global_key_str}")
                        print("======================================================================\n")
                    else:
                        print("-> No new bits were found with this trail, the search continues...")
                        
                    iteration += 1


                if sum(known_bits_mask) >= bits_to_find:
                    print(f"\n[SUCCESS] The number of known bits has reached the goal. Time elapsed : {elapsed_total:.2f} ")
                    if int(input("Would you like to bruteforce the rest of the key ? [0] for no, [1] for yes :")):
                        partial_key = [K_last[i] if known_bits_mask[i] else None for i in range(128)]
                        recovered_k_last, _ = tools.bruteforce_remaining_bits(K_last, partial_key)
                        
                        if recovered_k_last:
                            k_master_rec = recovered_k_last[:]
                             # Inverse key schedule so we can actually get the true key at the very end and not the key last
                            for _ in range(N_ROUNDS):
                                k_master_rec = gift.gift_inverse_key_schedule_128(k_master_rec)
                            
                            orig_hex = "".join(hex(sum(b << (3 - idx) for idx, b in enumerate(KEY[i:i+4])))[2:] for i in range(0, 128, 4)).upper()
                            rec_hex = "".join(hex(sum(b << (3 - idx) for idx, b in enumerate(k_master_rec[i:i+4])))[2:] for i in range(0, 128, 4)).upper()
                            print(f"\nMaster Key Recovery (GIFT-64):")
                            print(f"    Original Master Key : {orig_hex}")
                            print(f"    Recovered Master Key: {rec_hex}")
                            print(f"    Match: {orig_hex == rec_hex}")
                else:
                    print(f"\n[END] The attack stops with {sum(known_bits_mask)} known bits. Time elapsed : {elapsed_total:.2f}")

            elif choice == "4":
                for i in range(1, N_ROUNDS + 1):
                    K_last = present.present_key_schedule_80(K_last, i)
                
                known_bits_mask = [0] * 80
                excluded_final_masks = []
                iteration = 1
                bits_left = int(input("Acceptable number or remaining unknown bits :"))
                bits_to_find = 80 - bits_left
                
                print(f"--- STARTING RECURSIVE ATTACK ON PRESENT ---")
                print(f"Objective : Recover {bits_to_find} bits (Remaining <= 40 bits for quick bruteforce )\n")
                
                while sum(known_bits_mask) < bits_to_find:
                    print(f"\n--- Round {iteration} ---")
                    elapsed_total = time.time() - start_total_time
                    print(f"[Time Elapsed Since Start: {elapsed_total:.2f} seconds]")
                    # Looking for a new trail excluding previous ones
                    valid_trails = find_trail_milp_present(N_ROUNDS, LAT, excluded_final_masks)
                    if not valid_trails:
                        print("\nWARNING : No more linear paths were found by GUROBI")
                        break
                        
                    best_bias, best_initial, best_final = valid_trails[0]
                    excluded_final_masks.append(best_final)
                    
                    current_trail = {
                        'masks': [best_initial, best_final],
                        'total_log2_bias': best_bias,
                        'n_active_sboxes': sum(1 for i in range(16) if any(best_initial[i*4:i*4+4]))
                    }
                    
                    print(f"New trail found (Bias: {best_bias:.2f}). Attack in progress...")
                    recovered, influential_bits = attack_present_last_round(
                        pairs, current_trail, key_true=K_last)
                    
                    # Updates the known bits
                    new_bits_count = 0
                    for pos in influential_bits:
                        if known_bits_mask[pos] == 0:
                            known_bits_mask[pos] = 1
                            new_bits_count += 1
                            
                    if new_bits_count > 0:
                        print("\n======================= GLOBAL RECOVERY REPORT =======================")
                        print(f"Step {iteration} - Known bits of K_last : {sum(known_bits_mask)}/80")
                        global_key_str = "".join(str(K_last[i]) if known_bits_mask[i] else "?" for i in range(80))
                        print(f"\n{global_key_str}")
                        print("======================================================================\n")
                    else:
                        print("-> No new bits were found with this trail, the search continues...")
                        
                    iteration += 1

                if sum(known_bits_mask) >= bits_to_find:
                    print(f"\n[SUCCESS] The number of known bits has reached the goal. Time elapsed : {elapsed_total:.2f} ")
                    if int(input("Would you like to bruteforce the rest of the key ? [0] for no, [1] for yes :")):
                        partial_key = [K_last[i] if known_bits_mask[i] else None for i in range(80)]
                        recovered_k_last, _ = tools.bruteforce_remaining_bits(K_last, partial_key)
                        
                        if recovered_k_last:
                            k_master_rec = recovered_k_last[:]
                            # Inverse key schedule so we can actually get the true key at the very end and not the key last
                            for r in range(N_ROUNDS, 0, -1):
                                round_i_array = tools.int_to_bit_array(r, 5)
                                for idx in range(5):
                                    k_master_rec[79-19+idx] ^= round_i_array[idx]
                                k_master_rec[0:4] = present.std_rev_box_S[tools.array_to_4_tuple(k_master_rec[0:4])]
                                old_k = [0] * 80
                                for idx in range(80):
                                    old_k[79-((idx+19)%80)] = k_master_rec[79-idx]
                                k_master_rec = old_k
                            
                            orig_hex = "".join(hex(sum(b << (3 - idx) for idx, b in enumerate(KEY[i:i+4])))[2:] for i in range(0, 80, 4)).upper()
                            rec_hex = "".join(hex(sum(b << (3 - idx) for idx, b in enumerate(k_master_rec[i:i+4])))[2:] for i in range(0, 80, 4)).upper()
                            print(f"\nMaster Key Recovery (PRESENT-80):")
                            print(f"    Original Master Key : {orig_hex}")
                            print(f"    Recovered Master Key: {rec_hex}")
                            print(f"    Match: {orig_hex == rec_hex}")
                else:
                    print(f"\n[END] The attack stops with {sum(known_bits_mask)} known bits. Time elapsed : {elapsed_total:.2f}")

            input("\nPress enter to continue...")

        except FileNotFoundError as e:
            print(f"File not found: {e}")
            input("Press enter to continue...")
        except Exception as e:
            print(f"Error: {e}")
            input("Press enter to continue...")
        except KeyboardInterrupt:
            print("\nClosing Linear Cryptanalysis Application.")
            sys.exit(0)


if __name__ == "__main__":
    import os
    import sys
    import random
    main()