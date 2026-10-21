"""
Implementation of GIFT-64

gift_cipher(bit_array, key)
gift_decrypt(bit_array, key)
gift_one_round_64(bit_array, key, round_i)
gift_decrypt_one_round(bit_array, key, round_i)

std_box_S: dict
std_rev_box_S: dict
std_bit_perm: dict
std_rev_bit_perm: dict
"""

import tools as tools
import launcher as launcher


standard_box_S_conversion = [
    # Since all data manipulation are made on bit it is easier to do so too for the S boxs
    # (Even if the standard presentation of box S is in hexadecimal)
    # The convention used is big endian
    ([0,0,0,0],[0,0,0,1]), # 0 -> 1
    ([0,0,0,1],[1,0,1,0]), # 1 -> A = 10
    ([0,0,1,0],[0,1,0,0]), # 2 -> 4
    ([0,0,1,1],[1,1,0,0]), # 3 -> C = 12
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

std_box_S = {} # The standard S box used to encrypt the message
std_rev_box_S = {} # The reverse S box used to decrypt the message

for (a,b) in standard_box_S_conversion:
    std_box_S[tools.array_to_4_tuple(a)] = b
    std_rev_box_S[tools.array_to_4_tuple(b)] = a


standard_64_bit_permutation_conversion = [
    (0,0),(1,17),(2,34),(3,51),(4,48),(5,1),(6,18),(7,35),
    (8,32),(9,49),(10,2),(11,19),(12,16),(13,33),(14,50),(15,3),
    (16,4),(17,21),(18,38),(19,55),(20,52),(21,5),(22,22),(23,39),
    (24,36),(25,53),(26,6),(27,23),(28,20),(29,37),(30,54),(31,7),
    (32,8),(33,25),(34,42),(35,59),(36,56),(37,9),(38,26),(39,43),
    (40,40),(41,57),(42,10),(43,27),(44,24),(45,41),(46,58),(47,11),
    (48,12),(49,29),(50,46),(51,63),(52,60),(53,13),(54,30),(55,47),
    (56,44),(57,61),(58,14),(59,31),(60,28),(61,45),(62,62),(63,15)
]

std_bit_perm = {}
std_rev_bit_perm = {}

for (a,b) in standard_64_bit_permutation_conversion:
    std_bit_perm[a] = b
    std_rev_bit_perm[b] = a


def gift_key_schedule_128(key: list) -> list:
    """
    Key schedule for GIFT-64.
    Input : a 128 bit long array of the key, and the round number
    Output : the scheduled 128 bit long key for the next round
    """
    assert len(key) == 128
    W = [key[i*16 : i*16 + 16] for i in range(8)]

    # Active words are W[6]=k1 and W[7]=k0
    new_W = tools.ror16(W[6], 2) + tools.ror16(W[7], 12) + W[0] + W[1] + W[2] + W[3] + W[4] + W[5]
    return list(new_W)


def gift_one_round_64(bit_array: list, key: list, round_i: int = 0) -> list:
    """
    Input : a 64 bit long array to encrypt and a key in the same form of size 128
    Output : the encrypted array.
    """
    assert(len(bit_array) == 64 and len(key) == 128)

    box_S_step_array = [None] * 64
    for i in range(0, 64, 4):
        box_S_step_array[i:i+4] = std_box_S[tools.array_to_4_tuple(bit_array[i:i+4])]

    perm_array = [None] * 64
    for i in range(64):
        perm_array[63 - std_bit_perm[i]] = box_S_step_array[63 - i]

    W0 = key[112:128]
    W1 = key[96:112]

    result = perm_array[:]
    for j in range(16):
        result[63 - (4*j + 1)] ^= W1[15-j]  # bits have a different order than arrays
        result[63 - (4*j)]  ^= W0[15-j]

    result = add_round_constant(result, round_i)
    return result


def gift_n_round_64(bit_array: list, key: list, n: int, round_i: int = 0) -> list:
    """
    Input : a 64 bit long array to encrypt, a key in the same form of size 128 and the number of round n to apply
    Output : the encrypted array.
    """
    assert(n >= 0)
    if n == 0:
        return bit_array
    encrypted = gift_one_round_64(bit_array, key, round_i)
    next_key = gift_key_schedule_128(key)
    return gift_n_round_64(encrypted, next_key, n - 1, round_i + 1)


def gift_cipher(bit_array: list, key: list) -> list:
    """
    Input : a 64 bit long array to encrypt and a key in the same form of size 128
    Output : the encrypted array for 28 rounds.
    """
    return gift_n_round_64(bit_array, key, 28)


def gift_decrypt_one_round(bit_array: list, key: list, round_i: int) -> list:
    """
    Input : a 64 bit long array to decrypt and a key in the same form of size 128
    Output : the uncrypted array.
    """
    assert(len(bit_array) == 64 and len(key) == 128)

    # inverse secund part of AddRoundKey
    round_constant_added_array = add_round_constant(bit_array,round_i)    #TODO make sure round_i is the right number

    # inverse first part of AddRoundKey
    W0 = key[112:128]
    W1 = key[96:112]
    round_key_added_array = round_constant_added_array[:]
    for j in range(16):
        round_key_added_array[63 - (4*j + 1)] ^= W1[15-j]
        round_key_added_array[63 - (4*j)] ^= W0[15-j]

    # inverse PermBits
    unpermuted_array = [None] * 64
    for i in range(64):
        unpermuted_array[63 - std_rev_bit_perm[i]] = round_key_added_array[63 - i]

    # inverse SubCells
    decrypted_array = [None] * 64
    for i in range(0,64,4):
        decrypted_array[i:i+4] = std_rev_box_S[tools.array_to_4_tuple(unpermuted_array[i:i+4])]

# I don't understand what were these lines for so I rewrote them.
#    for i in range(64):
#        if std_64_bit_xor_placement[i]:
#            unpermuted_array[std_rev_bit_perm[i]] = bit_array[i] ^ key[i] # Xor is invertible : x ^ a ^ a = x for all a
#        else:
#            unpermuted_array[std_rev_bit_perm[i]] = bit_array[i]
#    for i in range(64):
#        unpermuted_array[std_rev_bit_perm[i]] = bit_array[i] ^ key[i]

    return decrypted_array


def gift_decrypt_n_round(bit_array: list, key: list, n:int) -> list:
    """
    Input : a 64 bit long array to decrypt, a key in the same form of size 128 and the number of round n to apply
    Output : the uncrypted array.
    """
    assert(n >= 0)
    assert(len(bit_array) == 64 and len(key) == 128)

    # TO-DO : Make a more efficient implementation for the key.
    scheduled_key_array = [[None]*128 for i in range(n+1)]
    scheduled_key_array[0] = key

    for i in range(n-1):
        scheduled_key_array[1+i] = gift_key_schedule_128(scheduled_key_array[i])

# I didn't understand this part so I got rid of it.
#    for i in range(64):
#        bit_array[i] = bit_array[i] ^ scheduled_key_array[n][16+i]

    for i in range(n):
        bit_array = gift_decrypt_one_round(bit_array,scheduled_key_array[n-i-1],n-i-1)

    return bit_array


def gift_decrypt(bit_array: list, key: list) -> list:
    """
    Input : a 64 bit long array to decrypt and a key in the same form of size 128
    Output : the uncrypted array for 28 rounds.
    """
    return gift_decrypt_n_round(bit_array, key, 28)


## Round constants


#def compute_round_constants() -> list:
#    """
#    Input : nothing
#    Output : all 28 round constants (GIFT-64 uses a 6-bit LFSR)
#    """
#    constants = []
#    rc = 0b000001
#    for _ in range(28):
#        constants.append(rc)
#        rc = tools.int_to_bit_array(rc,6)
#        tmp = rc[:]
#        for i in range(5):
#            rc[5-(i+1)] = tmp[5-i]
#        rc[5-0] = tmp[5-5]^tmp[5-4]^1
#        rc = tools.bit_array_to_int(rc)
#    return constants

# This code didn't work:
#    constants = []
#    rc = 0b000001  # initial LFSR state
#    for _ in range(28):
#        constants.append(rc)
#        # LFSR feedback: x^6 + x^5 + 1
#        feedback = ((rc >> 5) ^ (rc >> 4)) & 1
#        rc = ((rc << 1) & 0x3F) | feedback
#    return constants


#ROUND_CONSTANTS = compute_round_constants()
#print(ROUND_CONSTANTS)


ROUND_CONSTANTS = [0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,0x1E,0x3C,0x39,0x33,0x27,0x0E,0x1D,0x3A,0x35,0x2B,0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B]


# This code didn't work (even before I modified it)
#def add_round_constant(state: list, round_i: int) -> list:
#    """
#    Input : State of the cipher and number of the current round
#    Output : Updated state with the added LFSR constants
#    """
#    rc = ROUND_CONSTANTS[round_i]
#    result = state[:]
#    result[63-63] ^= 1
#    result[63-23] ^= (rc >> (5-0)) & 1
#    result[63-19] ^= (rc >> (5-1)) & 1
#    result[63-15] ^= (rc >> (5-2)) & 1
#    result[63-11] ^= (rc >> (5-3)) & 1
#    result[63-7]  ^= (rc >> (5-4)) & 1
#    result[63-3] ^= (rc >> (5-5)) & 1
#    return result


def add_round_constant(state: list, round_i: int) -> list:
    """
    Input : State of the cipher and number of the current round
    Output : Updated state with the added LFSR constants
    """
    rc = tools.int_to_bit_array(ROUND_CONSTANTS[round_i],6)
    result = state[:]
    result[63-63] ^= 1
    result[63-23] ^= rc[5-5]
    result[63-19] ^= rc[5-4]
    result[63-15] ^= rc[5-3]
    result[63-11] ^= rc[5-2]
    result[63-7] ^= rc[5-1]
    result[63-3] ^= rc[5-0]
    return result

#TODO to be tested
def gift_inverse_key_schedule_128(key: list) -> list:
    """
    Key schedule for GIFT-64.
    Input : a 128 bit long array of the key
    Output : the scheduled 128 bit long key for the former round
    """
    assert len(key) == 128
    W = [key[i*16 : i*16 + 16] for i in range(8)]

    # Active words are W[6]=k1 and W[7]=k0
    new_W = W[2] + W[3] + W[4] + W[5] + W[6] + W[7] + tools.ror16(W[0],14) + tools.ror16(W[1],4)

    return list(new_W)


menu = {
    "1": ("Encrypt"),
    "2": ("Encrypt N round"),
    "3": ("Decrypt"),
    "4": ("Decrypt N round"),
    "0": ("Quit", None),
}

def main():
    os.makedirs("testresults", exist_ok=True)

    while True:
        launcher.clear_screen()
        tools.print_menu("GIFT-64 Application", menu)

        try:
            choice = input("Choice: ").strip()

            if choice not in menu:
                print(f"Invalid choice: {choice}")
                input("Press enter to continue...")
                continue

            if choice == "0":
                print("Closing GIFT Application.")
                sys.exit(0)

            key = tools.read_key(32) 

            input_path = tools.choose_test_file()
            if input_path is None:
                input("Press enter to continue...")
                continue

            output_name = input("Output filename (in testfiles/): ").strip()
            if not output_name:
                print("Empty filename, operation cancelled.")
                input("Press enter to continue...")
                continue
            output_path = os.path.join("testfiles", output_name)

            nb_of_rounds = 28
            if choice in ("2", "4"):
                raw_n = input("Number of rounds: ").strip()
                if not raw_n.isdigit() or int(raw_n) < 0:
                    print("Invalid number of rounds.")
                    input("Press enter to continue...")
                    continue
                nb_of_rounds = int(raw_n)

            with open(input_path, "r", encoding="utf-8") as f:
                full_bit_array = tools.text_to_bit_array(f.read())

            padding_len = (64 - (len(full_bit_array) % 64)) % 64
            full_bit_array.extend([0] * padding_len)

            blocks = tools.split_bit_array(full_bit_array, 64)
            result = []

            for block in blocks:
                if choice in ("1", "2"):
                    res_block = gift_n_round_64(block, key, nb_of_rounds)
                else:
                    res_block = gift_decrypt_n_round(block, key, nb_of_rounds)
                result.extend(res_block)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(tools.bit_array_to_text(result))

            print(f"Result written to: {output_path}")
            
            print("\n" + "—" * 20 + " FILE CONTENT " + "—" * 20)
            os.system(f"cat '{output_path}'")
            print("\n" + "—" * 54 + "\n")

            input("Press enter to continue...")

        except FileNotFoundError as e:
            print(f"File not found: {e}")
            input("Press enter to continue...")
        except Exception as e:
            print(f"Error: {e}")
            input("Press enter to continue...")
        except KeyboardInterrupt:
            print("\nClosing GIFT Application.")
            sys.exit(0)


if __name__ == "__main__":
    print("Program launched successfully")
    main()









