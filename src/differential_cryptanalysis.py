# This module aims to implement the methods that will be used for differential attacks.

#!/usr/bin/env sage -python
from tools import bit_array_to_int, int_to_bit_array, xor_arrays, tuple_4_to_array, array_to_4_tuple, hamming_weight, generate_random_bit_array, split_bit_array
from sage.all import *
from random import randint
import time
from math import log2
import gurobipy as gp
from gurobipy import GRB
import numpy as np
import gift_cipher as gift
import present_cipher_64_bit as present
import tools


# TO-DO : make sure there is no reference issue for array.


def DDT(box_S: dict, n: int) -> list[list[int]]:
    """
    Input : A box_S of size 2^(n)
    Output : The DDT table of the box_S as a matrix of the size of the S_box
    """

    size = 2 ** n
    ddt_array = [[0]*size for i in range(size)]

    for i in range(size):
        bit_array_in = int_to_bit_array(i, n)
        for j in box_S.keys():
            bit_array_x = box_S[j]
            bit_array_x_xor_in = box_S[array_to_4_tuple(xor_arrays([tuple_4_to_array(j), bit_array_in]))]
            ddt_array[i][bit_array_to_int(xor_arrays([bit_array_x, bit_array_x_xor_in]))] += 1

    return ddt_array


def generate_transition(ddt: list[list[int]]) -> tuple[list[list[int]],list[list[int]]]:
    """
    Input : A DDT matrix of size (n,n) and n = 2^m
    Output : The list of (impossible or not) transition in the form [x1, ... ,xn,y1, ... ,yn]
    """

    n = len(ddt)
    m = int(log2(n))

    assert(len(ddt[0]) == n)

    lst_trans = [] # Allocate staticly later on ?
    lst_imp_trans = []

    for i in range(n):
        for j in range(n):
            x_in = int_to_bit_array(i, m)
            y_out = int_to_bit_array(j, m)
            transition = [0]*8
            for k in range(m):
                transition[k] = x_in[m-1-k]
                transition[k+m] = y_out[m-1-k]

            if ddt[i][j] != 0:
                lst_trans.append(transition)
            else:
                lst_imp_trans.append(transition)

    return (lst_trans, lst_imp_trans)


def generate_inequalities(lst_trans: list[list[int]]) -> list[list[int]]:
    """
    Input : A list of n transition of size 2*m
    Output : A list of n inequalities in the form of [e0, ... ,em] which represent 
            e0 + e1*x0 + ... em*x(m-1) + e(m+1)*y0 + ... e(2m)*y(m-1) >= 0
    """

    A_polyhedron = Polyhedron(vertices=lst_trans)

    lst_inequality = []

    for ieq in A_polyhedron.inequality_generator():
        lst_inequality.append(ieq)

    return lst_inequality


def removed_impossible_transition(inequality: list[int], lst_imp_trans: list[list[int]]) -> list[list[int]]:
    """
    Input : An inequality and a list of impossible transition
    Output : The list of impossible transition removed by the inequality
    """

    lst_rmv_imp_trans = []
    
    n = len(lst_imp_trans)
    m = len(lst_imp_trans[0])

    for i in range(n):
        sum = inequality[0]
        for j in range(m):
            sum += inequality[j+1] * lst_imp_trans[i][j]
        
        if sum < 0:
            lst_rmv_imp_trans.append(lst_imp_trans[i].copy())

    return lst_rmv_imp_trans


def greedy_convex_hull(lst_inequality: list[list[int]], lst_imp_trans: list[list[int]], n: int) -> list[list[int]]:
    """
    Input:
        lst_inequality: the set of all inequalities in the H-representation of the convex hull of an S-box;
        lst_imp_trans: the set of all impossible differential patterns of an S-box;
        n: a positive integer.
    Output: The set of n inequalities selected from lst_inequality
    """

    assert(len(lst_inequality) >= n)

    lst_slct_inequality = []

    for i in range(n):
        ind_max_rmv_ieq = 0
        max_rmv_ieq = removed_impossible_transition(lst_inequality[0], lst_imp_trans)

        for j in range(len(lst_inequality)-1):
            rmv_ieq = removed_impossible_transition(lst_inequality[j+1], lst_imp_trans)
            if len(rmv_ieq) > len(max_rmv_ieq):
                max_rmv_ieq = rmv_ieq
                ind_max_rmv_ieq = j+1
        
        for j in range(len(max_rmv_ieq)):
            lst_imp_trans.remove(max_rmv_ieq[j])
        
        lst_slct_inequality.append(lst_inequality[ind_max_rmv_ieq]) # Vérifier les effets de bords ici !!!!!!
        lst_inequality.remove(lst_inequality[ind_max_rmv_ieq])
        
    return lst_slct_inequality


def greedy_convex_hull_2(lst_inequality: list[list[int]], lst_imp_trans: list[list[int]]) -> list[list[int]]:
    """
    Input:
        lst_inequality: the set of all inequalities in the H-representation of the convex hull of an S-box;
        lst_imp_trans: the set of all impossible differential patterns of an S-box;
    Output: The set of n inequalities selected from lst_inequality that remove all impossible pattern
    """

    lst_slct_inequality = []

    while len(lst_imp_trans) > 0 and len(lst_inequality) > 0: #No infinite loop.
        ind_max_rmv_ieq = 0
        max_rmv_ieq = removed_impossible_transition(lst_inequality[0], lst_imp_trans)

        for j in range(len(lst_inequality)-1):
            rmv_ieq = removed_impossible_transition(lst_inequality[j+1], lst_imp_trans)
            if len(rmv_ieq) > len(max_rmv_ieq):
                max_rmv_ieq = rmv_ieq
                ind_max_rmv_ieq = j+1
        
        for j in range(len(max_rmv_ieq)):
            lst_imp_trans.remove(max_rmv_ieq[j])
        
        lst_slct_inequality.append(lst_inequality[ind_max_rmv_ieq]) # Vérifier les effets de bords ici !!!!!!
        lst_inequality.remove(lst_inequality[ind_max_rmv_ieq])
        
    return lst_slct_inequality


def blocking_formula(imp_trans: list[int]) -> list[int]:
    """
    Input : An impossible transition in the form of [x0, ..., x(m-1), y0, ..., y(m-1)]
    Output : An inequality removing the impossible transition in the form of [e0, ... ,em] which represent 
            e0 + e1*x0 + ... em*x(m-1) + e(m+1)*y0 + ... e(2m)*y(m-1) >= 0
    """

    n = len(imp_trans) # n = 2m
    ieq = [0]*(n+1)

    ieq[0] = hamming_weight(imp_trans) - 1

    for i in range(n):
        if imp_trans[i] == 0:
            ieq[i+1] = 1
        elif imp_trans[i] == 1:
            ieq[i+1] = -1

    return ieq


def merge_imp_trans(lst_imp_trans: list[list[int]], n: int) -> list[list[int]]:
    """
    Input : An impossible transition list, and a number of try n to merge two patterns
    Output : An impossible transition list with merged pattern
    NB : We use 2 for start
    """

    merge_imp_trans = lst_imp_trans.copy()
    p = len(lst_imp_trans[0])

    for i in range(n):
        m = len(merge_imp_trans)
        i1 = randint(0,m-1)
        i2 = randint(0,m-1)

        if i1 != i2:
            nb_diff = 0
            imptrans1 = merge_imp_trans[i1].copy()
            imptrans2 = merge_imp_trans[i2].copy()
            merged_trans = merge_imp_trans[i1].copy()
            for j in range(p):
                if merge_imp_trans[i2][j] != merge_imp_trans[i1][j]:
                    nb_diff += 1
                    merged_trans[j] = 2
            if nb_diff <= 1:
                merge_imp_trans.remove(imptrans1)
                merge_imp_trans.remove(imptrans2)
                merge_imp_trans.append(merged_trans)

    return merge_imp_trans


def milp_minimize_active_s_box(lst_ieq: list[list[int]], bit_perm: dict, number_of_s_box: int, number_of_bit: int, number_of_round: int, details: int=0, min_nb_sol: int=1, pool_nb_sol: int=1) -> tuple[int, list[int], list[int]]:
    """
    Input : 
    - A list of inequalities describing the S box
    - The bit permutation used in the cipher
    - The number of S box used per round in the cipher
    - The number of bit used by the cipher in input for each s box
    - The number of round for the computation
    - (If details = 1 then print console log)
    - (Describe the minimum number of solutions)
    - (Describe a pool of solutions possible of a certain maximum size)
    Output : The minimum number of active S box and a first configuration giving this minimization

    Nb : using Gurobi solver
    Nb : we are using a linear representation for s box
    """

    nr = number_of_round
    nb = number_of_bit # per s box
    ns = number_of_s_box

    p = gp.Model("Min active S box")

    p.Params.LogToConsole = details  # Hides optimization details only
    p.Params.PoolSearchMode = min_nb_sol
    p.Params.PoolSolutions = pool_nb_sol

    S = p.addMVar(shape=(nr+1)*ns, vtype=GRB.BINARY, name="Sbox") # Make the (nr+1) x ns array into a (nr+1)*ns one, [r,i] -> r*ns + i
    B = p.addMVar(shape=(nr+1)*(ns*nb), vtype=GRB.BINARY, name="Bits") # Same idea (see as a matrix of 4 tuplet all permutation are settled at each round)

    A = np.concatenate((np.array([-1]*ns*nb), np.zeros((nr*ns*nb,), dtype=int))) 
    p.addConstr(A @ B <= np.array([-1]), name="First line") # At least one bit should be changed.

    for ieq in lst_ieq:
        for r in range(nr):
            # We give must have a transition if there is bit activated upstream
            # We must activate a S box
            # We must make sure permutation are done right
            for s in range(ns):
                # We use bit for each s box to make sure the ieq hold with our transition
                # lst = [d_0, x_0, ... , x_n-1, y_0, ..., y_n-1] -> A * B >= -d_0
                A = np.array([0]*(nr+1)*(ns*nb))
                C = np.array([0]*(nr+1)*(ns*nb)) 
                D = np.array([0]*(nr+1)*(ns))
                for i in range(nb):
                    A[r*(ns*nb) + s*nb + i] = -ieq[nb-i]
                    A[(r+1)*(ns*nb) + bit_perm[s*nb + i]] = -ieq[2*nb-i]
                    C[r*(ns*nb) + s*nb + i] = 1

                D[r*ns + s] = 1

                p.addConstr(A @ B <= np.array([ieq[0]]), name="IEQ S box")
                p.addConstr(C @ B - (nb * D) @ S <= np.array([0]), name="S box activation 1")
                p.addConstr(D @ S - C @ B <= np.array([0]), name="S box activation 2")

    obj_sum = np.concatenate((np.array([1]*(nr*ns)), np.zeros((ns,), dtype=int)))
    p.setObjective(obj_sum @ S, GRB.MINIMIZE)
    p.optimize()

    return (int(p.ObjVal), S.X.astype(int), B.X.astype(int))


def milp_minimize_active_s_box_diff(input_diff: (list[int],bool), output_diff: (list[int],bool), lst_ieq: list[list[int]], bit_perm: dict, number_of_s_box: int, number_of_bit: int, number_of_round: int, details: int=0, min_nb_sol: int=1, pool_nb_sol: int=10, gap: float=0.0) -> list[tuple[int, list[int], list[int]]]:
    """
    Input : 
    - The input difference and if it need to be used or not
    - The output difference (given after permutation) and if it need to be used or not
    - A list of inequalities describing the S box
    - The bit permutation used in the cipher
    - The number of S box used per round in the cipher
    - The number of bit used by the cipher in input for each s box
    - The number of round for the computation (nr >= 1)
    - (If details = 1 then print console log)
    - (Describe the minimum number of solutions)
    - (Describe a pool of solutions possible of a certain maximum size)
    - (The maximum gap autorized)
    Output : 
    - A list containing all the solution found

    Nb : using Gurobi solver
    Nb : we are using a linear representation for s box
    """

    nr = number_of_round
    nb = number_of_bit # per s box
    ns = number_of_s_box

    p = gp.Model("Min active S box")

    p.Params.LogToConsole = details  # Hides optimization details only
    p.Params.PoolSearchMode = min_nb_sol
    p.Params.PoolSolutions = pool_nb_sol
    p.Params.PoolGap = gap

    S = p.addMVar(shape=(nr+1)*ns, vtype=GRB.BINARY, name="Sbox") # Make the (nr+1) x ns array into a (nr+1)*ns one, [r,i] -> r*ns + i
    B = p.addMVar(shape=(nr+1)*(ns*nb), vtype=GRB.BINARY, name="Bits") # Same idea (see as a matrix of 4 tuplet all permutation are settled at each round)

    A = np.concatenate((np.array([-1]*ns*nb), np.zeros((nr*ns*nb,), dtype=int))) 
    p.addConstr(A @ B <= np.array([-1]), name="First line") # At least one bit should be changed.
    for i in range(ns*nb):
        T1 = np.zeros(((nr+1)*ns*nb,), dtype=int)
        T2 = np.zeros(((nr+1)*ns*nb,), dtype=int)
        T1[i] = 1
        T2[nr*ns*nb + i] = 1
        if input_diff[1]:
            p.addConstr(T1 @ B == np.array(input_diff[0][i]), name="Set diff") # The input and output difference are set
        if output_diff[1]:
            p.addConstr(T2 @ B == np.array(output_diff[0][i]), name="Set diff") # The input and output difference are set

    for ieq in lst_ieq:
        for r in range(nr):
            # We give must have a transition if there is bit activated upstream
            # We must activate a S box
            # We must make sure permutation are done right
            for s in range(ns):
                # We use bit for each s box to make sure the ieq hold with our transition
                # lst = [d_0, x_0, ... , x_n-1, y_0, ..., y_n-1] -> A * B >= -d_0
                A = np.array([0]*(nr+1)*(ns*nb))
                C = np.array([0]*(nr+1)*(ns*nb)) 
                D = np.array([0]*(nr+1)*(ns))
                for i in range(nb):
                    A[r*(ns*nb) + s*nb + i] = -ieq[nb-i]
                    A[(r+1)*(ns*nb) + bit_perm[s*nb + i]] = -ieq[2*nb-i]
                    C[r*(ns*nb) + s*nb + i] = 1

                D[r*ns + s] = 1

                p.addConstr(A @ B <= np.array([ieq[0]]), name="IEQ S box")
                p.addConstr(C @ B - (nb * D) @ S <= np.array([0]), name="S box activation 1")
                p.addConstr(D @ S - C @ B <= np.array([0]), name="S box activation 2")

    obj_sum = np.concatenate((np.array([1]*(nr*ns)), np.zeros((ns,), dtype=int)))
    p.setObjective(obj_sum @ S, GRB.MINIMIZE)
    p.optimize()

    # 2. Retrieve solutions
    sol_lst = [(0,[],[])]*p.SolCount

    for k in range(p.SolCount):
        p.Params.SolutionNumber = k # Set which solution to retrieve
        sol_lst[k] = (p.PoolObjVal, S.PoolNX.astype(int)[:-1], B.PoolNX.astype(int))

    return sol_lst


def trail_probability(ddt: list[list[int]], s_box_trail: list[int], bit_trail: list[int], bit_perm: dict, number_of_s_box: int, number_of_bit: int, number_of_round: int) -> int:
    """
    Input :
    - The DDT
    - The trail of S boxs 
    - The bit trail
    - The bit perm
    - The number of S box used per round in the cipher
    - The number of bit used by the cipher in input for each s box
    - The number of round for the computation (nr >= 1)
    Output : The probability of the trail.
    """

    n = len(ddt)
    nr = number_of_round
    nb = number_of_bit # per s box
    ns = number_of_s_box

    res = 1.
    lst_bit = [split_bit_array(bit_trail[nb*ns*j:nb*ns*(j+1)],nb) for j in range(nr+1)]

    for i in range(nr):
        for j in range(ns):
            if s_box_trail[i*ns + j] == 1:
                ddt_in = bit_array_to_int(lst_bit[i][j])
                temp = [0]*nb
                for k in range(nb):
                    temp[k] = bit_trail[(i+1)*ns*nb + bit_perm[j*nb+k]]
                    #print(k)
                    #print(j*nb+k)
                    #print(bit_perm[j*nb+k])
                    #print(bit_trail[(i+1)*ns*nb:(i+2)*ns*nb])

                """
                for ind in range(64):
                    if bit_trail[(i+1)*ns*nb + ind] == 1:
                        print(ind)
                """

                ddt_out = bit_array_to_int(temp)
                #print(ddt_in)
                #print(ddt_out)
                #print(temp)
                assert(ddt[ddt_in][ddt_out] >= 1)
                res *= ddt[ddt_in][ddt_out] / n

    return res


def probability_total(ddt: list[list[int]], set_of_trail: list[tuple[int, list[int], list[int]]], bit_perm: dict, number_of_s_box: int, number_of_bit: int, number_of_round: int) -> int:
    """
    Input :
    - The DDT
    - A set of trail
    - The bit perm
    - The number of S box used per round in the cipher
    - The number of bit used by the cipher in input for each s box
    - The number of round for the computation (nr >= 1)
    Output : The probability of the trail.
    """

    n = len(set_of_trail)
    lst_proba = [0.]*n

    for i in range(n):
        s_box_trail = set_of_trail[i][1]
        bit_trail = set_of_trail[i][2]
        lst_proba[i] = trail_probability(ddt, s_box_trail, bit_trail, bit_perm, number_of_s_box, number_of_bit, number_of_round)

    return np.sum(np.array(lst_proba),dtype="float64")


def differential_in_out(lst: list[tuple[list[int], list[int]]]):
    """
    Input : A list of (input,output) of length n >= 2
    Output : A list of (delta input, delta output, inputs numbers) of length = n(n-1)/2
    """

    n = len(lst)
    assert(n > 1)
    lst_res = [([],[],(0,0))]*(n*(n-1)/2)
    ind = 0
    for i in range(n-1):
        for j in range(i+1,n):
            lst_res[ind] = (xor_arrays([lst[i][0],lst[j][0]]), xor_arrays([lst[i][1],lst[j][1]]), (i,j))
            ind += 1

    return lst_res


def differential_full_distinguisher(nb_round_tackle: int, threshold: int, cipher_data, lst_path, filename: string) -> bool:
    """
    Input  :
    - The number of round to perform in order to distinguish some pattern.
    - The name of the file which will contain the results.
    - The cipher chosen threshold (usually 2^-n)
    - The lst_path [(input,output)]
    - Needed cipher data ...       
    Output : 
    - The distinguished pattern for the cipher written [text,text]->probabily,true/false (if passed the threshold) in the file
    - Return a boolean if something is worth doing it.
    """
    
    t = time.time()
    ind = 1

    ddt, bit_perm, nb_s_box, nb_bit, nb_round, lst_ieq, cipher_name = cipher_data
    threshold_passed = False

    with open(filename, 'w', encoding='utf-8') as file:
        file.write("Differential Attack on " + cipher_name + " : number of round user = " + str(nb_round_tackle) + " , number of path = " + str(len(lst_path)) + " , threshold = " + str(threshold) + "\n")

        for path_tuple in lst_path:
            # put a try later with at least one path found and no path found exception.
            try:
                lst_trail = milp_minimize_active_s_box_diff((path_tuple[0],True), (path_tuple[1],True), lst_ieq, bit_perm, nb_s_box, nb_bit, nb_round_tackle, pool_nb_sol=1000, min_nb_sol=10) 
                res = probability_total(ddt, lst_trail, bit_perm, nb_s_box, nb_bit, nb_round_tackle)
                res_bool_s = "False"
                if (res > 2. ** (-threshold)):
                    res_bool_s = "True"
                    threshold_passed = True

                file.write(str(path_tuple[0]) + "," + str(path_tuple[1]) + "," + str(res) + "," + res_bool_s + "," + str(time.time() - t) + "\n")
                print(str(ind) + " : " + str(time.time() - t) + "," + str(res) + "," + res_bool_s + "\n")
                ind += 1
                t = time.time()
            except:
                file.write(str(path_tuple[0]) + "," + str(path_tuple[1]) + ",Error," + str(time.time() - t) + "\n")
                print(str(ind) + " : " + str(time.time() - t) + ",Error\n")
                ind += 1
                t = time.time()

    return threshold_passed


def differential_full_distinguisher_opt(nb_round_tackle: int, threshold: int, cipher_data, lst_path, filename: string, k1: int=5, k2: int=5) -> bool:
    """
    Input  :
    - The number of round to perform in order to distinguish some pattern.
    - The name of the file which will contain the results.
    - The cipher chosen threshold (usually 2^-n)
    - The lst_path [input]
    - Needed cipher data ...       
    Output : 
    - The distinguished pattern for the cipher written [text,text]->probabily,true/false (if passed the threshold) in the file
    - Return a boolean if something is worth doing it.
    """
    
    t0 = time.time()
    ind = 1

    ddt, bit_perm, nb_s_box, nb_bit, nb_round, lst_ieq, cipher_name = cipher_data
    threshold_passed = False

    temp = []
    for path in lst_path:
        temp.extend(milp_minimize_active_s_box_diff((path,True), ([0]*nb_bit*nb_s_box,False), lst_ieq, bit_perm, nb_s_box, nb_bit, nb_round_tackle, pool_nb_sol=k1, min_nb_sol=2))
    lst_path2 = [(b[0:nb_bit*nb_s_box],b[nb_bit*nb_s_box*nb_round_tackle:nb_bit*nb_s_box*(1+nb_round_tackle)]) for (t,s,b) in temp]

    t = time.time()

    with open(filename, 'w', encoding='utf-8') as file:
        file.write("Differential Attack on " + cipher_name + " : number of round user = " + str(nb_round_tackle) + " , number of path = " + str(len(lst_path)) + " , threshold = " + str(threshold) + "\n")

        for path_tuple in lst_path2:
            # put a try later with at least one path found and no path found exception.
            try:
                lst_trail = milp_minimize_active_s_box_diff((path_tuple[0],True), (path_tuple[1],True), lst_ieq, bit_perm, nb_s_box, nb_bit, nb_round_tackle, pool_nb_sol=k2, min_nb_sol=2) 
                res = probability_total(ddt, lst_trail, bit_perm, nb_s_box, nb_bit, nb_round_tackle)
                res_bool_s = "False"
                if (res > 2. ** (-threshold)):
                    res_bool_s = "True"
                    threshold_passed = True

                showed = "Try : " + str(ind) + " | Input : " + tools.bit_array_to_hex(path_tuple[0]) + " -> Output : " + tools.bit_array_to_hex(path_tuple[1]) + " | Probability = " + str(res) + " | Passed the threshold : " + res_bool_s + " | Exec time = " + str(time.time() - t) + "s\n"
                file.write(showed)
                print(showed)
                ind += 1
                t = time.time()
            except:
                showed = "Try : " + str(ind) + " | Input : " + tools.bit_array_to_hex(path_tuple[0]) + " -> Output : " + tools.bit_array_to_hex(path_tuple[1]) + " | Error | Exec time = " + str(time.time() - t) + "s\n"
                file.write(showed)
                print(showed)
                ind += 1
                t = time.time()
            
        file.write("\nFull run time : " + str(t - t0) + "s")

    return threshold_passed


def differential_full_distinguisher_gift(nb_round_tackle: int, threshold: int, lst_path, filename: string) -> bool:
    """
    Input  :
    - The number of round to perform in order to distinguish some pattern.
    - The name of the file which will contain the results.
    - The cipher chosen threshold (usually 2^-n)
    - The lst_path [(input,output)]       
    Output : 
    - The distinguished pattern for the cipher written [text,text]->probabily,true/false (if passed the threshold) in the file
    - Return a boolean if something is worth doing it.
    """
    
    ddt = DDT(gift.std_box_S,4)
    lst_trans, lst_imp_trans = generate_transition(ddt)
    lst_ieq = greedy_convex_hull_2(generate_inequalities(lst_trans),lst_imp_trans)
    cipher_data = (ddt, gift.std_bit_perm, 16, 4, 28, lst_ieq, "GIFT-64")
    return differential_full_distinguisher(nb_round_tackle, threshold, cipher_data, lst_path, filename)


def differential_full_distinguisher_gift_opt(nb_round_tackle: int, threshold: int, lst_path, filename: string) -> bool:
    """
    Input  :
    - The number of round to perform in order to distinguish some pattern.
    - The name of the file which will contain the results.
    - The cipher chosen threshold (usually 2^-n)
    - The lst_path [(input,output)]       
    Output : 
    - The distinguished pattern for the cipher written [text,text]->probabily,true/false (if passed the threshold) in the file
    - Return a boolean if something is worth doing it.
    """
    
    ddt = DDT(gift.std_box_S,4)
    lst_trans, lst_imp_trans = generate_transition(ddt)
    lst_ieq = greedy_convex_hull_2(generate_inequalities(lst_trans),lst_imp_trans)
    cipher_data = (ddt, gift.std_bit_perm, 16, 4, 28, lst_ieq, "GIFT-64")
    return differential_full_distinguisher_opt(nb_round_tackle, threshold, cipher_data, lst_path, filename)


def differential_full_distinguisher_present(nb_round_tackle: int, threshold: int, lst_path, filename: string) -> bool:
    """
    Input  :
    - The number of round to perform in order to distinguish some pattern.
    - The name of the file which will contain the results.
    - The cipher chosen threshold (usually 2^-n)
    - The lst_path [(input,output)]       
    Output : 
    - The distinguished pattern for the cipher written [text,text]->probabily,true/false (if passed the threshold) in the file
    - Return a boolean if something is worth doing it.
    """
    
    ddt = DDT(present.std_box_S,4)
    lst_trans, lst_imp_trans = generate_transition(ddt)
    lst_ieq = greedy_convex_hull_2(generate_inequalities(lst_trans),lst_imp_trans)
    cipher_data = (ddt, present.std_bit_perm, 16, 4, 31, lst_ieq, "Present")
    return differential_full_distinguisher(nb_round_tackle, threshold, cipher_data, lst_path, filename)



def print_sbox_trail(S_vals, num_rounds, num_sboxes=16):
    """
    Graphically displays the active S-boxes in the terminal.
    """
    print("\n" + "=" * 60)
    print("               ACTIVE S-BOX TRAIL VISUALIZATION")
    print("=" * 60)
    # Print header numbers
    header = "          "
    for i in range(num_sboxes):
        header += f"{i:2d} "
    print(header)
    print("-" * 60)
    
    for r in range(num_rounds):
        row_str = f"Round {r+1:02d} |"
        for s in range(num_sboxes):
            val = S_vals[r * num_sboxes + s]
            # Use '##' for active S-boxes, '..' for inactive
            row_str += " ##" if val == 1 else " .."
        print(row_str)
    print("=" * 60 + "\n")


def differential_full_distinguisher_present_opt(nb_round_tackle: int, threshold: int, lst_path, filename: string) -> bool:
    """
    Input  :
    - The number of round to perform in order to distinguish some pattern.
    - The name of the file which will contain the results.
    - The cipher chosen threshold (usually 2^-n)
    - The lst_path [(input,output)]       
    Output : 
    - The distinguished pattern for the cipher written [text,text]->probabily,true/false (if passed the threshold) in the file
    - Return a boolean if something is worth doing it.
    """
    
    ddt = DDT(present.std_box_S,4)
    lst_trans, lst_imp_trans = generate_transition(ddt)
    lst_ieq = greedy_convex_hull_2(generate_inequalities(lst_trans),lst_imp_trans)
    cipher_data = (ddt, present.std_bit_perm, 16, 4, 31, lst_ieq, "Present")
    return differential_full_distinguisher_opt(nb_round_tackle, threshold, cipher_data, lst_path, filename)

"""
menu = {
    "1": ("Count min active S-boxes on GIFT-64 (MILP)"),
    "2": ("Count min active S-boxes on PRESENT-80 (MILP)"),
    "3": ("Automated Random Distinguisher Search on GIFT-64"),
    "4": ("Automated Random Distinguisher Search on PRESENT-80"),
    "0": ("Quit", None),
}
"""
main_menu = {
    "1": "Differential attack on GIFT-64",
    "2": "Differential attack on PRESENT",
    "0": "Quit"
}

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        tools.print_menu("Differential Cryptanalysis Application", main_menu)

        try:
            choice = input("Choice: ").strip()

            if choice not in main_menu:
                print(f"Invalid choice: {choice}")
                input("Press enter to continue...")
                continue

            if choice == "0":
                print("Closing Differential Cryptanalysis Application.")
                sys.exit(0)

            if choice == "1":
                cipher_name = "GIFT-64"
                box_S = gift.std_box_S
                bit_perm = gift.std_bit_perm
                distinguisher_func = differential_full_distinguisher_gift
                distinguisher_opt_func = differential_full_distinguisher_gift_opt
            elif choice == "2":
                cipher_name = "PRESENT"
                box_S = present.std_box_S
                bit_perm = present.std_bit_perm
                distinguisher_func = differential_full_distinguisher_present
                distinguisher_opt_func = differential_full_distinguisher_present_opt

            number_of_s_box = 16
            number_of_bit = 4
            block_size = 64

            sub_menu = {
                "1": f"Count min active S-boxes on {cipher_name} (MILP)",
                "2": f"Automated Random Distinguisher Search on {cipher_name} (non optimized)",
                "3": f"Automated Random Distinguisher Search on {cipher_name} (optimized)",
                "0": "Back to Main Menu"
            }

            tools.print_menu(f"Differential on {cipher_name}", sub_menu)
            sub_choice = input("Choice: ").strip()

            if sub_choice == "0":
                continue
            if sub_choice not in sub_menu:
                print(f"Invalid choice: {sub_choice}")
                input("Press enter to continue...")
                continue

            # --- COLLECTE DES ARGUMENTS COMMUNS ---
            raw_n = input("Number of rounds: ").strip()
            if not raw_n.isdigit() or int(raw_n) < 1:
                print("Invalid number of rounds.")
                input("Press enter to continue...")
                continue
            nb_of_rounds = int(raw_n)

            # --- EXECUTION SELON LE MODE CHOISI ---
            
            # 1. Nombre minimal de S-boxes actives
            if sub_choice == "1":
                ddt = DDT(box_S, number_of_bit)
                lst_trans, lst_imp_trans = generate_transition(ddt)
                lst_ieq = generate_inequalities(lst_trans)
                lst_slct_ieq = greedy_convex_hull_2(lst_ieq, lst_imp_trans)

                obj_val, S_vals, B_vals = milp_minimize_active_s_box(
                    lst_slct_ieq, bit_perm, number_of_s_box, number_of_bit, nb_of_rounds
                )
                print(f"\nMinimum number of active S-boxes over {nb_of_rounds} rounds for {cipher_name}: {obj_val}")
                print_sbox_trail(S_vals, nb_of_rounds, number_of_s_box)

            # 2. Recherche automatique de distinguo (Non optimisée)
            elif sub_choice == "2":
                raw_pairs = input("Number of random paths/pairs to generate: ").strip()
                if not raw_pairs.isdigit() or int(raw_pairs) < 1:
                    print("Invalid number of pairs.")
                    input("Press enter to continue...")
                    continue
                num_pairs = int(raw_pairs)

                raw_t = input("Threshold exponent t (2^-t) [default 64]: ").strip()
                threshold = int(raw_t) if raw_t.isdigit() else 64

                filename = input("Output filename [default: automated_diff_results.txt]: ").strip()
                if not filename:
                    filename = "automated_diff_results.txt"

                # Génération des paires aléatoires requises par l'argument lst_path
                lst_path = [(tools.generate_random_bit_array(block_size), tools.generate_random_bit_array(block_size)) for _ in range(num_pairs)]

                # Appel direct du programme autonome
                distinguisher_func(nb_of_rounds, threshold, lst_path, filename)

            # 3. Recherche automatique de distinguo (Optimisée par poids de Hamming)
            elif sub_choice == "3":
                raw_k = input("Hamming weight for input differences generation (e.g., 1 or 2): ").strip()
                if not raw_k.isdigit() or int(raw_k) < 0:
                    print("Invalid Hamming weight.")
                    input("Press enter to continue...")
                    continue
                k_weight = int(raw_k)
                max_essai = int(input("Entrer le nombre d'essai maximum: "))
                raw_t = input("Threshold exponent t (2^-t) [default 64]: ").strip()
                threshold = int(raw_t) if raw_t.isdigit() else 64
                k1 = int(input("Entrer K1 (parametre de recherche): "))
                k2 = int(input("Entrer K2 (parametre de recherche): "))



                filename = input("Output filename [default: automated_diff_results.txt]: ").strip()
                if not filename:
                    filename = "automated_diff_results.txt"

                # Génération déterministe basée uniquement sur le poids de Hamming demandé
                lst_path = tools.generate_bit_array_diff(block_size, k_weight)

                # Appel direct du programme autonome optimisé
                distinguisher_opt_func(nb_of_rounds, threshold, lst_path[0:min(max_essai,len(lst_path))], filename)

            input("\nExecution completed. Press enter to continue...")

        except Exception as e:
            print(f"Error: {e}")
            input("Press enter to continue...")
        except KeyboardInterrupt:
            print("\nClosing Differential Cryptanalysis Application.")
            sys.exit(0)


if __name__ == "__main__":
    import os
    import sys
    print("Program launched successfully")
    main()


if __name__ == "__main__":
    import os
    import sys
    print("Program launched successfully")
    main()