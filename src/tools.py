# This module aims to support the transformation from text to bit array and the opposite

import random

#TO-DO : Recheck if bits are in the right order
#TO-DO : Check the functions resize_key and split_bit_array
#TO-DO : for split_bit_array, is '0' equivalent to the 'None' character ?

random.seed()
import time
import launcher as launcher
import random
import os

def array_to_4_tuple(array: list) -> tuple:
    """
    Input : A 4 bit array
    Output : The associated tuple
    """
    assert(len(array) == 4)
    return (array[0],array[1],array[2],array[3])


def array_to_tuple(array: list) -> tuple:
    """
    Input : A n bit array
    Output : The associated tuple
    """
    return tuple(array)


def tuple_4_to_array(tuple_4: tuple) -> list[int]:
    """
    Input : A 4 bit tuple
    Output : The associated array
    """
    a,b,c,d = tuple_4
    return [a,b,c,d]


def xor_arrays(array_list: list[list[int]]) -> list[int]:
    """
    Input : a list of array of the same size n
    Output : the result of all the array xored.
    """
    n = len(array_list)

    assert(n > 0)

    length = len(array_list[0])
    xor_array = [0]*length

    for i in range(n):
        assert(len(array_list[i]) == length)
        for j in range(length):
            xor_array[j] = xor_array[j] ^ array_list[i][j]

    return xor_array


def and_arrays(array_list: list[list[int]]) -> list[int]:
    """
    Input : a list of array of the same size n
    Output : the result of all the array and-ed
    """
    n = len(array_list)

    assert(n > 0)

    length = len(array_list[0])
    and_array = [1]*length

    for i in range(n):
        assert(len(array_list[i]) == length)
        for j in range(length):
            and_array[j] = and_array[j] & array_list[i][j]

    return and_array


def xor_reduce(array: list[int]) -> int:
    """
    Input: a list of ints
    Output: the result of every bit XORed
    """
    r = 0
    for bit in array:
        r ^= bit
    return r

def dot_bit_arrays(a: list[int], b: list[int]) -> int:
    return xor_reduce([x & y for x, y in zip(a, b)])

def xor_two_arrays(a: list[int], b: list[int]) -> list[int]:
    assert len(a) == len(b)
    return [x ^ y for x, y in zip(a, b)]

def incr_bit_array(array: list[int]):
    """
    Input: a number represented in binary form
    Output: that number increased by one
    """

    i = len(array) - 1
    while i >= 0:
        if array[i] == 0:
            array[i] = 1
            return
        else:
            array[i] = 0  # carry
            i -= 1
    return


def int_to_bit_array(n: int, size: int = 0) -> list[int]:
    """
    Input : a number n and the size of the bit array
    Output : n % (2^size) in bit array

    If size = 0 or if there is no size, then the size is automatically determined.
    """
    assert(size >= 0 and n >= 0)

    if size == 0:
        n_tmp = n
        while n_tmp > 0:
            n_tmp = n_tmp // 16
            size += 1
        size *= 4

    bit_array = [0]*size

    for i in range(size):
        bit_array[size-i-1] = n % 2
        n = n // 2

    return bit_array


def bit_array_to_int(bit_array: list[int]) -> int:
    """
    Input : a bit array
    Output : the number linked
    """

    n = 0
    power = 1
    length = len(bit_array)

    for i in range(length):
        n += bit_array[length-i-1] * power
        power *= 2

    return n


def bits_number(n: int) -> int:
    """
    Input : a number as an int
    Output : the minimal number of bits required to represent this number
    """
    d = 1
    while 2**d < n:
        d += 1
    return d


def char_to_bit_array(char: str) -> list:
    """
    Input : An utf-8 character
    Output : An array of bits of length 8.
    """
    assert(len(char) == 1)

    bit_array = [0]*8
    char_in_int = format(ord(char),'b')

    assert(len(char_in_int) <= 8)

    char_in_int = '0' * (8 - len(char_in_int)) + char_in_int

    for i in range(8):
        bit_array[i] = int(char_in_int[i])

    return bit_array


def bit_array_to_char(bit_array: list) -> str:
    """
    Input : An array of bits of length 8.
    Output : An utf-8 character
    """
    assert(len(bit_array) == 8)

    return chr(int("0b" + ("".join(map((lambda x: str(x)), bit_array))), 2))


def text_to_bit_array(text: str) -> list:
    """
    Input : A text composed of utf-8 characters.
    Output : An array of bits which length is a multiple of 8.
    """
    n = len(text)
    bit_array = [None]*(n*8)

    for i in range(n):
        bit_array[i*8:(i+1)*8] = char_to_bit_array(text[i])

    return bit_array


def bit_array_to_text(bit_array: list) -> str:
    """
    Input : An array of 0 or 1 which length is a multiple of 8.
    Output : A text composed of utf-8 characters.
    """
    assert(len(bit_array) % 8 == 0)
    return "".join([bit_array_to_char(bit_array[i:i+8]) for i in range(0, len(bit_array), 8) ])


def bit_array_to_hex(bit_array: list) -> str:
    """
    Input : An array of 0 or 1 which length is a multiple of 4.
    Output : A text composed of utf-8 characters.
    """
    assert(len(bit_array) % 4 == 0)
    return "".join([hex(bit_array_to_int(bit_array[i:i+4]))[2:] for i in range(0, len(bit_array), 4)])


def resize_key(key: list, new_size: int) -> list:
    """
    Input : A key to be resized as an array, the new size as an int.
    Output : The resized key as an array.
    """
    returned_key = []
    for i in range(new_size):
        returned_key.append(key[i%len(key)])
    return returned_key


# WARNING: I've commented some lines because they caused bugs. Please check I didn't break your code.
def split_bit_array(bit_array: list, block_size: int) -> list:
    """
    Input : A message to be split as a bit array, a size of blocks as an int.
    Output : The message as a list of bit array of size block_size.
    """
    assert len(bit_array) % block_size == 0

    returned_list = []
    for i in range(len(bit_array)//block_size):
        partial_bit_array = []
        for j in range(block_size):
            partial_bit_array.append(bit_array[i*block_size+j])
        returned_list.append(partial_bit_array)
    #for j in range(len(bit_array)%block_size):
    #    partial_bit_array.append(bit_array[-(len(bit_array)%block_size)+j])
    #partial_bit_array += [0]*(block_size-len(bit_array)%block_size)
    #returned_list.append(partial_bit_array)
    return returned_list


def ror16(bits: list, r: int) -> list:
    """
    Input : 16 bit array
    Output : Right rotation of the 16 bit array by r positions."""
    r = r % 16
    if r == 0:
        return bits[:]
    n = bit_array_to_int(bits)
    rotated = ((n >> r) | (n << (16 - r))) & 0xFFFF
    return int_to_bit_array(rotated, 16)


def compute_round_constants() -> list:
    """
    Input : nothing
    Output : all 28 round constants (GIFT-64 uses a 6-bit LFSR)
    """
    constants = []
    rc = 0b000001  # initial LFSR state
    for _ in range(28):
        constants.append(rc)
        # LFSR feedback: x^6 + x^5 + 1
        feedback = ((rc >> 5) ^ (rc >> 4)) & 1
        rc = ((rc << 1) & 0x3F) | feedback
    return constants


ROUND_CONSTANTS = compute_round_constants()


def add_round_constant(state: list, round_i: int) -> list:
    """
    Input : State of the cipher and number of the current round
    Output : Updated state with the added LFSR constants
    """
    rc = ROUND_CONSTANTS[round_i]
    result = state[:]
    result[63] ^= (rc >> 0) & 1
    result[23] ^= (rc >> 1) & 1
    result[19] ^= (rc >> 2) & 1
    result[15] ^= (rc >> 3) & 1
    result[11] ^= (rc >> 4) & 1
    result[7]  ^= (rc >> 5) & 1
    result[47] ^= 1
    return result


"""

    partial_bit_array = []
    for i in range((len(bit_array)//block_size)*block_size + 1, len(bit_array)):
        partial_bit_array.append(bit_array[i])
    returned_list.append(partial_bit_array)
    partial_bit_array = []

    if len(returned_list[-1]) < block_size :
        returned_list[-1] += [0 for i in range(block_size - len(returned_list[-1]))]
"""


def array_formatting(bit_array : list, block_size : int):
    if len(bit_array) == block_size :
        return(bit_array)
    if len(bit_array) < block_size :
        bit_array += [0 for i in range(block_size - len(bit_array))]
    else :
        return(bit_array[:block_size])
    return(bit_array)


def hamming_weight(bit_array: list[int]) -> int:
    """
    Input : an array of 0 and 1 and * (* represent an unknown bit and is encoded with anyother integer)
    Output : the hamming weight of the array (where only 1 are counted)
    """
    weight = 0
    for i in bit_array:
        if i == 1:
            weight += 1

    return weight

def generate_random_bit_array(n: int) -> list[int]:
    """
    Input : The length of the array
    Output : The randomized array
    """
    lst = [0]*n
    for i in range(n):
        lst[i] = random.randint(0,1)

    return lst


def generate_bit_array_diff(n: int, k: int) -> list[list[int]]:
    """
    Input : the length of arrays, and the number of one generated.
    Output : The list of all array generated with a 
    """
    assert(n >= k)

    if n == k:
        return [[1]*n]

    if k == 0:
        return [[0]*n]

    if k == 1:
        return [(([0]*i) + [1]) + ([0]*(n-i-1)) for i in range(n)]
        
    t1 = [[0]+l for l in generate_bit_array_diff(n-1,k)]
    t2 = [[1]+l for l in generate_bit_array_diff(n-1,k-1)]

    return t1 + t2


def bruteforce_remaining_bits(key_true: list[int], key_partial: list) -> tuple[list[int], float]:
    """
    Brute forces the missing bits of a partial key in the format [?,0,1,0,1,1,?,?,?,?,0,1]
    """
    # Conversion step so the function is both compatible standalone or queued with the recursive attack
    if isinstance(key_partial, str):
        processed_partial = []
        for char in key_partial:
            if char == '?':
                processed_partial.append(None)
            else:
                processed_partial.append(int(char))
    else:
        processed_partial = [None if b == '?' else b for b in key_partial]

    key_size = len(key_true)
    assert len(key_partial) == key_size, "La clé réelle et la clé partielle doivent avoir la même taille !"
    unknown_indices = [i for i, bit in enumerate(key_partial) if bit == '?' or bit is None]
    num_unknown = len(unknown_indices)

    print(f"Starting bruteforce on {num_unknown} remaining bits (Key size: {key_size} bits)...")

    start_time = time.time()
    current_guess = [0 if b == '?' or b is None else b for b in key_partial]

    if current_guess == key_true:
        time_taken = time.time() - start_time
        binary_str = "".join(map(str, current_guess))
        hex_str = "".join(hex(sum(b << (3 - idx) for idx, b in enumerate(current_guess[i:i+4])))[2:] for i in range(0, len(current_guess), 4)).upper()
        print("Key found on the very first try (all zeros)!")
        print(f"Key (Bin) : {binary_str}")
        print(f"Key (Hex) : {hex_str}")
        return current_guess, time_taken
    unknown_bits_state = [0] * num_unknown

    # Total number of iterations (2^num_unknown - 1)
    total_combinations = (1 << num_unknown) - 1

    for iteration in range(total_combinations): # Fun fact : j'ai réutilisé le code de l'additionneur qu'on a vu en cours de INF107 bit a bit
        for i in range(num_unknown):
            if unknown_bits_state[i] == 0:
                unknown_bits_state[i] = 1
                break
            else:
                unknown_bits_state[i] = 0 # La retenue

        for idx_in_unknown, idx_in_key in enumerate(unknown_indices):
            current_guess[idx_in_key] = unknown_bits_state[idx_in_unknown]

        if current_guess == key_true:
            time_taken = time.time() - start_time
            binary_str = "".join(map(str, current_guess))
            hex_str = "".join(hex(sum(b << (3 - idx) for idx, b in enumerate(current_guess[i:i+4])))[2:] for i in range(0, len(current_guess), 4)).upper()
            print("Key found successfully!")
            print(f"Key (Bin) : {binary_str}")
            print(f"Key (Hex) : {hex_str}")
            return current_guess, time_taken

    time_taken = time.time() - start_time
    print("Key not found. Please check if the partial key is correct.")
    return [], time_taken
    
key_sizes = {
    "1": ("GIFT-64  / AES (128 bits)", 32),
    "2": ("PRESENT-80 (80 bits)", 20),
}

def print_menu(title, menu):
    print("\n" + "=" * 50)
    print(title)
    if mykey_hex:
        print(f"Current key: {mykey_hex}")
    else:
        print("Current key: None")
    print("=" * 50 + "\n")
    for key, val in menu.items():
        name = val if isinstance(val, str) else val[0]
        print(f"  [{key}] {name}")
    print("\n" + "-" * 50)


def choose_test_file():
    os.makedirs("testfiles", exist_ok=True)
    files = sorted(f for f in os.listdir("testfiles") if os.path.isfile(os.path.join("testfiles", f)))
    if not files:
        print("No files found in testfiles/")
        return None
    print("\nAvailable files in testfiles/:")
    for i, f in enumerate(files, start=1):
        print(f"  [{i}] {f}")
    raw = input("File number: ").strip()
    if not raw.isdigit() or not (1 <= int(raw) <= len(files)):
        print("Invalid choice.")
        return None
    return os.path.join("testfiles", files[int(raw) - 1])

mykey_hex = None

def read_key(key_hex_size):
    global mykey, mykey_hex
    print("\n  [1] Custom key")
    print("  [2] Random key\n")
    choice = input("Choice: ").strip()
    while True:
        if choice == "1":
            raw = input(f"Key ({key_hex_size} hex chars): ").strip().lower()
        else:
            raw = ''.join(random.choice("0123456789abcdef") for _ in range(key_hex_size))
            print(f"Generated key: {raw}")
        if len(raw) == key_hex_size and all(c in "0123456789abcdef" for c in raw):
            bits = []
            for c in raw:
                bits.extend(int_to_bit_array(int(c, 16), 4))
            mykey_hex = raw
            mykey = bits
            return bits
        print(f"Invalid key, please enter exactly {key_hex_size} hex characters.")

def generate_random_key():
    print("\nChoose cipher :")
    for k, (name, size) in key_sizes.items():
        print(f"  [{k}] {name} -> {size} hex chars")
    choice = input("Choice: ").strip()
    if choice not in key_sizes:
        print("Invalid choice.")
        return
    name, size = key_sizes[choice]
    key = ''.join(random.choice("0123456789abcdef") for _ in range(size))
    print(f"\nGenerated key : {key}")


def create_plaintext_file():
    os.makedirs("testfiles", exist_ok=True)
    filename = input("Filename (in testfiles/): ").strip()
    if not filename:
        print("Empty filename, operation cancelled.")
        return
    content = input("Content: ").strip()
    filepath = os.path.join("testfiles", filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"File written to: {filepath}")

menu = {
    "1": ("Generate random key"),
    "2": ("Create plaintext file in testfiles/"),
    "3": ("Bruteforce a partial key"),
    "0": ("Quit", None),
}

def main():
    while True:
        launcher.clear_screen()
        print_menu("Tools Application", menu)

        try:
            choice = input("Choice: ").strip()

            if choice not in menu:
                print(f"Invalid choice: {choice}")
                input("Press enter to continue...")
                continue

            if choice == "0":
                print("Closing Tools Application.")
                sys.exit(0)

            if choice == "1":
                generate_random_key()
            elif choice == "2":
                create_plaintext_file()

            input("\nPress enter to continue...")

        except Exception as e:
            print(f"Error: {e}")
            input("Press enter to continue...")
        except KeyboardInterrupt:
            print("\nClosing Tools Application.")
            sys.exit(0)


if __name__ == "__main__":
    import os
    import sys
    import random
    print("Program launched successfully")
    main()
