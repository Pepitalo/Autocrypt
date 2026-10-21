"""
PRESENT-80 implementation

present_cipher(bit_array,key)
present_decrypt(bit_array,key)
present_one_round(bit_array, key)
present_decrypt_one_round(bit_array, key)

std_box_s: dict
std_rev_box_s: dict
std_bit_perm: dict
std_rev_bit_perm: dict
"""

from tools import array_to_4_tuple, int_to_bit_array, text_to_bit_array, bit_array_to_text, split_bit_array
import launcher as launcher
import tools as tools

standard_box_S_conversion = [
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

std_box_S = {} # The standard S box used to encrypt the message
std_rev_box_S = {} # The reverse S box used to decrypt the message

for (a,b) in standard_box_S_conversion:
    std_box_S[array_to_4_tuple(a)] = b
    std_rev_box_S[array_to_4_tuple(b)] = a

standard_permutation_conversion = [None]*64

for i in range(16):
    standard_permutation_conversion[i*4] = i
    standard_permutation_conversion[1+i*4] = 16 + i
    standard_permutation_conversion[2+i*4] = 32 + i
    standard_permutation_conversion[3+i*4] = 48 + i

std_bit_perm = {}
std_rev_bit_perm = {}

for a in range(len(standard_permutation_conversion)):
    std_bit_perm[a] = standard_permutation_conversion[a]
    std_rev_bit_perm[standard_permutation_conversion[a]] = a


def present_key_schedule_80(key: list, round_i: int) -> list:
    """
    Input : a 80 bit long array of the key, and the round number    # K=[k79,k78,...,k0]
    Output : the scheduled 80 bit long key for the next step
    """
    new_key = [0] * 80

    for i in range(80):
        new_key[79-i] = key[79-((i+19)%80)]

    new_key[0:4] = std_box_S[array_to_4_tuple(new_key[0:4])]

    round_i_array = int_to_bit_array(round_i,5)

    for i in range(5):
        new_key[79-19+i] = new_key[79-19+i]^round_i_array[i]

    return new_key


def present_one_round(bit_array: list, key: list) -> list:
    """
    Input : a 64 bit long array to encrypt and a key in the same form of size 80
    Output : the encrypted array.
    """
    assert(len(bit_array) == 64 and len(key) == 80)

    xor_array = [None] * 64
    box_S_step_array = [None] * 64
    encrypted_array = [None] * 64

    for i in range(64):
        xor_array[63-i] = bit_array[63-i] ^ key[79-(16+i)]

    for i in range(0,64,4):
        box_S_step_array[i:i+4] = std_box_S[array_to_4_tuple(xor_array[i:i+4])]

    for i in range(64):
        encrypted_array[std_bit_perm[i]] = box_S_step_array[i]

    return encrypted_array


def present_n_round(bit_array: list, key: list, n:int) -> list:
    """
    Input : a 64 bit long array to encrypt, a key in the same form of size 80 and the number of rounds n to apply
    Output : the encrypted array.
    """
    assert(n >= 0)
    assert(len(bit_array) == 64 and len(key) == 80)

    for i in range(1,n+1):
        bit_array = present_one_round(bit_array,key)
        key = present_key_schedule_80(key, i)

    for i in range(64):
        bit_array[63-i] = bit_array[63-i] ^ key[79-(16+i)]

    return bit_array


def present_cipher(bit_array: list, key: list) -> list:
    """
    Input : a 64 bit long array to encrypt, a key in the same form of size 80
    Output : the encrypted array, for 31 rounds.
    """
    return present_n_round(bit_array, key, 31)


def present_decrypt_one_round(bit_array: list, key: list) -> list:
    """
    Input : a 64 bit long array to decrypt and a key in the same form of size 80
    Output : the uncrypted array.
    """
    assert(len(bit_array) == 64 and len(key) == 80)

    unpermuted_array = [None] * 64
    box_S_step_array = [None] * 64
    decrypted_array = [None] * 64

    for i in range(64):
        unpermuted_array[std_rev_bit_perm[i]] = bit_array[i]

    for i in range(0,64,4):
        box_S_step_array[i:i+4] = std_rev_box_S[array_to_4_tuple(unpermuted_array[i:i+4])]

    for i in range(64):
        decrypted_array[63-i] = box_S_step_array[63-i] ^ key[79-(16+i)] # Xor is invertible : x ^ a ^ a = x for all a

    return decrypted_array


def present_decrypt_n_round(bit_array_to_be_decrypted: list, key: list, n:int) -> list:
    """
    Input : a 64 bit long array to decrypt and a key in the same form of size 80 and the number of rounds n to decrypt
    Output : the uncrypted array.
    """
    bit_array = bit_array_to_be_decrypted.copy()    # so that there is no side effect

    assert(n >= 0)
    assert(len(bit_array) == 64 and len(key) == 80)

    # TO-DO : Make a more efficient implementation for the key.
    scheduled_key_array = [[None]*80 for i in range(n+1)]
    scheduled_key_array[0] = key    # scheduled_key_array = [K1,K2,...,K32]

    for i in range(1,n+1):
        scheduled_key_array[i] = present_key_schedule_80(scheduled_key_array[i-1],i)

    for i in range(64):
        bit_array[63-i] = bit_array[63-i] ^ scheduled_key_array[n][79-(16+i)]

    for i in range(n):
        bit_array = present_decrypt_one_round(bit_array,scheduled_key_array[n-i-1])

    return bit_array


def present_decrypt(bit_array: list, key: list) -> list:
    """
    Input : a 64 bit long array to decrypt and a key in the same form of size 80
    Output : the uncrypted array for 31 rounds.
    """
    return present_decrypt_n_round(bit_array, key, 31)

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
        tools.print_menu("PRESENT Application", menu)

        try:
            choice = input("Choice: ").strip()

            if choice not in menu:
                print(f"Invalid choice: {choice}")
                input("Press enter to continue...")
                continue

            if choice == "0":
                print("Closing PRESENT Application.")
                sys.exit(0)

            key = tools.read_key(20)

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

            nb_of_rounds = 31
            if choice in ("2", "4"):
                raw_n = input("Number of rounds: ").strip()
                if not raw_n.isdigit() or int(raw_n) < 0:
                    print("Invalid number of rounds.")
                    input("Press enter to continue...")
                    continue
                nb_of_rounds = int(raw_n)

            with open(input_path, "r", encoding="utf-8") as f:
                full_bit_array = text_to_bit_array(f.read())

            padding_len = (64 - (len(full_bit_array) % 64)) % 64
            full_bit_array.extend([0] * padding_len)

            blocks = split_bit_array(full_bit_array, 64)
            result = []

            for block in blocks:
                if choice in ("1", "2"):
                    res_block = present_n_round(block, key, nb_of_rounds)
                else:
                    res_block = present_decrypt_n_round(block, key, nb_of_rounds)
                result.extend(res_block)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(bit_array_to_text(result))

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

