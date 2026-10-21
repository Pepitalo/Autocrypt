# Tests for MILP.

from src.milp_aes import AES_min_active_s_box,AES_min_active_s_box_optimized
import time



# test given for AES
lst_AES_min_kn = [1, 5, 9, 25, 26, 30, 34, 50, 51, 55, 59, 75, 76, 80]


t = time.time()

for i in range(7): # 7 already take up to 9 sec, I don't have the patience to wait for the 8th test to finish.
    print("Test : " + str(i+1))
    assert(AES_min_active_s_box(i+1) == lst_AES_min_kn[i])
    print("Temps d'execution :" + str(time.time()-t))
    t = time.time()

for i in range(len(lst_AES_min_kn)):
    print("Test : " + str(i+1))
    assert(AES_min_active_s_box_optimized(i+1, 1) == lst_AES_min_kn[i])
    print("Temps d'execution :" + str(time.time()-t))
    t = time.time()
