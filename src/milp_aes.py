# Implemantation of MILP for AES.

#!/usr/bin/env sage -python 
from sage.all import *
import gurobipy as gp
from gurobipy import GRB
import numpy as np



def AES_min_active_s_box(n: int) -> int:
    """
    Input : The number of round for the computation
    Output : The minimum number of active S box

    NB : do not go further than 8.
    Nb : using sage solver.
    """
    rounds = range(n)

    p = MixedIntegerLinearProgram(maximization=False)
    S = p.new_variable(name='sbox', binary=True)
    M = p.new_variable(name='mcol', binary=True)

    for r in rounds:
        for j in range(4):
            activecells = sum(S[r,i,(i+j)%4] for i in range(4)) + sum(S[r+1,i,j] for i in range(4))
            p.add_constraint(5*M[r,j] <= activecells <= 8*M[r,j])

    p.add_constraint(sum(S[0,i,j] for i in range(4) for j in range(4)) >= 1)
    p.set_objective(sum(S[r,i,j] for r in rounds for i in range(4) for j in range(4)))
    p.solve()

    # print(p.get_objective_value(), p.get_values(S))
    return(int(p.get_objective_value()))


def AES_min_active_s_box_optimized(n: int, details: int=0) -> int:
    """
    Input : The number of round for the computation, (If details = 1 then print console log)
    Output : The minimum number of active S box

    Nb : using gurobi solver.
    """
    rounds = range(n)

    p = gp.Model("AES_min_kn")

    p.Params.LogToConsole = details  # Hides optimization details only

    S = p.addMVar(shape=(n+1)*16, vtype=GRB.BINARY, name="Sbox") # Make the nx4x4 array into a n*4*4 one, [r,i,j] -> r*16 + i*4 + j
    M = p.addMVar(shape=n*4, vtype=GRB.BINARY, name="Mcol") # Make the nx4 into a n*4 one, [r,j] -> r*4 + j

    for r in rounds:
        for j in range(4):
            rhs = np.array([0, 0])
            A = np.array(([0]*((n+1)*16),[0]*((n+1)*16)))
            B = np.array(([0]*n*4,[0]*n*4))
            B[0][4*r+j] = 8
            B[1][4*r+j] = -5
            for i in range(4):
                A[0][r*16 + i*4 + ((i+j)%4)] += 1
                A[0][(r+1)*16 + i*4 + j] += 1
                A[1][r*16 + i*4 + ((i+j)%4)] += -1
                A[1][(r+1)*16 + i*4 + j] += -1
            p.addConstr(A @ S  -  B @ M <= rhs, name="M["+str(r)+","+str(j)+"]:")

    A = np.concatenate((np.array([-1]*16), np.zeros((n*16,), dtype=int)))
    p.addConstr(A @ S <= np.array([-1]), name="Fist line")

    obj_sum = np.concatenate((np.array([1]*(n*16)), np.zeros((16,), dtype=int)))
    p.setObjective(obj_sum @ S, GRB.MINIMIZE)
    p.optimize()

    return int(p.ObjVal)
    
if __name__ == "main" :
    print("Program launched sucessfully")
