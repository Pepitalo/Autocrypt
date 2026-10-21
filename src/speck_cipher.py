"""
Code of the Speck cipher.

speck(n,m,x,y,l,k): encrypt the (x,y) bit array with the (l,k) key.
inverse_speck(n,m,x,y,l,k): decrypt the (x,y) bit array with the (l,k) key.
speck_one_round_encryption(n,x,y,k,alpha,beta,i): encrypt one round the (x,y) bit array with parameter (alpha,beta) on round i.
speck_one_round_decryption(n,x,y,k,alpha,beta,i): decrypt one round the (x,y) bit array with parameter (alpha,beta) on round i.

speck_bit_perm(n,input): a function that modelizes the Speck bit permutation.
SPECK_BIT_PERM_n(n): a function that modelizes the Speck bit permutation.
speck_s_box(n,input): a function that modelizes the Speck S-box.
SPECK_S_BOX_n(n): a function that builds a dict representing the S-box.

Please check the values of (alpha,beta) in the code of 'speck' if you need.

# In one round :
# - Step 1 : equivalent bit permutation
# - Step 2 : equivalent S-box
# - Step 3 : add round key
"""


from tools import xor_two_arrays, int_to_bit_array, text_to_bit_array, bit_array_to_text
import tools
import launcher


def speck(n: int, m: int, x: list[int], y: list[int], l: list[list[int]], k: list[list[int]]) -> list[int]:
    """
    'Speck block_size / key_size' (in bits)
    block_size = 2 * n
    key_size = n * m

    n: word size (in {16; 24; 32; 48; 64})
    m: number of key words (depending on n)
    T: number of rounds (depending on n)
    x, y: plaintext words
    l[m-2]...l[0], k[0]: key words

    l and k are expanded in place.
    """

    T = T_n_m(n, m)

    assert(T != 0)

    if n == 16:
        alpha, beta = 7, 2
    else:
        alpha, beta = 8, 3

    key_expansion(n, m, T, l, k, alpha, beta)

    return encryption(n, T, x, y, k, alpha, beta)


def inverse_speck(n: int, m: int, x: list[int], y: list[int], l: list[list[int]], k: list[list[int]]) -> list[int]:
    """
    Inverse of speck.
    """

    T = T_n_m(n, m)

    if n == 16:
        alpha, beta = 7, 2
    else:
        alpha, beta = 8, 3

    key_expansion(n, m, T, l, k, alpha, beta)

    return decryption(n, T, x, y, k, alpha, beta)


def key_expansion(n: int, m: int, T: int, l: list[list[int]], k: list[list[int]], alpha: int, beta: int):
    """
    Expands l and k in place.
    """
    for i in range(T):
        tmp = S(-alpha,l[i])
        tmp = addition(n, k[i], tmp)
        tmp = xor(tmp, int_to_bit_array(i, n))
        l.append(tmp)
        tmp = S(beta, k[i])
        tmp = xor(tmp, l[i+m-1])
        k.append(tmp)


def speck_one_round_encryption(n: int, x: list[int], y: list[int], k: list[list[int]], alpha: int, beta: int, i: int) -> tuple[list[int]]:
    """
    i: round index

    One round of encryption of x and y.
    """
    x_tmp, y_tmp = x.copy(), y.copy()
    x_tmp = S(-alpha, x_tmp)
    x_tmp = addition(n, x_tmp, y_tmp)
    x_tmp = xor(x_tmp, k[i])
    y_tmp = S(beta, y_tmp)
    y_tmp = xor(y_tmp, x_tmp)
    return x_tmp, y_tmp


def speck_one_round_decryption(n: int, x: list[int], y: list[int], k: list[list[int]], alpha: int, beta: int, i: int) -> tuple[list[int]]:
    """
    One round decryption of x and y.
    """
    x_tmp, y_tmp = x.copy(), y.copy()
    y_tmp = xor(y_tmp, x_tmp)
    y_tmp = S(-beta, y_tmp)
    x_tmp = xor(x_tmp, k[i])
    x_tmp = substraction(n, x_tmp, y_tmp)
    x_tmp = S(+alpha, x_tmp)
    return x_tmp, y_tmp


def encryption(n: int, T: int, x: list[int], y: list[int], k:list[list[int]], alpha: int, beta: int) -> tuple[list[int]]:
    """
    Encryption of x and y.
    """
    x_tmp, y_tmp = x.copy(), y.copy()
    for i in range(T):
        x_tmp, y_tmp = speck_one_round_encryption(n, x_tmp, y_tmp, k, alpha, beta, i)
    return x_tmp, y_tmp


def decryption(n: int, T: int, x: list[int], y: list[int], k:list[list[int]], alpha: int, beta: int) -> tuple[list[int]]:
    """
    Decryption of x and y.
    """
    x_tmp, y_tmp = x.copy(), y.copy()
    for i in range(T-1,-1,-1):
        x_tmp, y_tmp = speck_one_round_decryption(n, x_tmp, y_tmp, k, alpha, beta, i)
    return x_tmp, y_tmp


## Steps


def xor(x: list[int], y: list[int]) -> list[int]:
    """Bitwise XOR."""
    return xor_two_arrays(x, y)


def addition(n: int, x: list[int], y: list[int]) -> list[int]:
    """Addition modulo 2^n."""
    tmp = [0] * n
    c = 0
    for i in range(n):
        tmp[n-1-i] = x[n-1-i] ^ y[n-1-i] ^ c
        c = (x[n-1-i] & (y[n-1-i] | c)) | (y[n-1-i] & c)
    return tmp


def substraction(n: int, x: list[int], y: list[int]) -> list[int]:
    """
    Substraction modulo 2^n.
    x - y
    """
    tmp = [0] * n
    for i in range(n):
        tmp[n-1-i] = 1 - y[n-1-i]
    tmp = addition(n, tmp, [0] * (n-1) + [1])  # two's complement of y
    tmp = addition(n, x, tmp)
    return tmp


def S(j: int, x: list[int]) -> list[int]:
    """Circular shift by j bits to the left (or -j bits to the right)."""
    tmp = x.copy()
    if j>0:
        for _ in range(j):
            tmp.append(tmp.pop(0))
    elif j<0:
        for _ in range(-j):
            tmp.insert(0,tmp.pop())
    return tmp


def T_n_m(n: int, m: int) -> int:
    """Returns T depending on n and m. 0 if m is not compatible with n."""
    if n == 16:
        if m == 4:
            return 22
        else:
            return 0
    elif n == 24:
        if m == 3:
            return 22
        elif m == 4:
            return 23
        else:
            return 0
    elif n == 32:
        if m == 3:
            return 26
        if m == 4:
            return 27
        else:
            return 0
    elif n == 48:
        if m == 2:
            return 28
        if m == 3:
            return 29
        else:
            return 0
    elif n == 64:
        if m == 2:
            return 32
        elif m == 3:
            return 33
        elif m == 4:
            return 34
        else:
            return 0
    else:
        return 0


## Bonus : equivalent S-box and bit permutation


# In one round :
# - Step 1 : bit permutation
# - Step 2 : S-box
# - Step 3 : add round key


def speck_bit_perm(n: int, input: tuple[int]) -> tuple[int]:
    """
    n: word size
    input: a tuple of bits of length 2*n
    """
    if n == 16:
        alpha, beta = 7, 2
    else:
        alpha, beta = 8, 3
    x_tmp = list(input)[:n]
    y_tmp = list(input)[n:]
    x_tmp = S(-alpha, x_tmp)
    return tuple(x_tmp+y_tmp)


def SPECK_BIT_PERM_n(n: int) -> dict:
    """
    n: word size
    input: a tuple of bits of length 2*n
    """
    SPECK_bit_perm = {}
    for i in range(2**(2*n)):
        bit_tuple = tuple(int_to_bit_array(i, 2*n))
        SPECK_BIT_PERM[bit_tuple] = speck_s_box(n,bit_tuple)
    return SPECK_BIT_PERM


def speck_s_box(n: int, input: tuple[int]) -> tuple[int]:
    """
    n: word size
    input: a tuple of bits of length 2*n
    """
    if n == 16:
        alpha, beta = 7, 2
    else:
        alpha, beta = 8, 3
    x_tmp = list(input)[:n]
    y_tmp = list(input)[n:]
    x_tmp = addition(n, x_tmp, y_tmp)
    y_tmp = S(beta, y_tmp)
    y_tmp = xor(x_tmp, y_tmp)
    return tuple(x_tmp+y_tmp)


def SPECK_S_BOX_n(n: int) -> dict:
    """
    n: word size
    output: the dict[tuple->tuple] corresponding to the S-box
    """
    SPECK_S_BOX = {}
    for i in range(2**(2*n)):
        bit_tuple = tuple(int_to_bit_array(i, 2*n))
        SPECK_S_BOX[bit_tuple] = speck_s_box(n,bit_tuple)
    return SPECK_S_BOX

VALID_PARAMS = {
    16: [4],
    24: [3, 4],
    32: [3, 4],
    48: [2, 3],
    64: [2, 3, 4],
}

def select_n_and_m() -> tuple[int, int] | None:
    """
    Interactive menus to select n then m.
    Returns (n, m) or None
    """
    n_options = list(VALID_PARAMS.keys())
    print("\n  Word size n (block = 2n bits, key = n*m bits):")
    for i, val in enumerate(n_options, 1):
        print(f"    [{i}] n = {val} (block {2*val} bits)")
    print("    [0] Cancel")

    raw = input("Choice: ").strip()
    if raw == "0":
        return None
    if not raw.isdigit() or not (1 <= int(raw) <= len(n_options)):
        print("Invalid choice.")
        return None
    n = n_options[int(raw) - 1]

    m_options = VALID_PARAMS[n]
    if len(m_options) == 1:
        m = m_options[0]
        print(f"  m = {m} (only option for n={n})")
    else:
        print(f"\n  Choose m :")
        for i, val in enumerate(m_options, 1):
            print(f"    [{i}] m = {val} (key {n*val} bits)")
        print("    [0] Cancel")

        raw = input("Choice: ").strip()
        if raw == "0":
            return None
        if not raw.isdigit() or not (1 <= int(raw) <= len(m_options)):
            print("Invalid choice.")
            return None
        m = m_options[int(raw) - 1]

    print(f"\n  Selected: n={n}, m={m} : block={2*n} bits : key={n*m} bits : rounds={T_n_m(n,m)}")
    return n, m

def split_key(raw_key_bits: list[int], n: int, m: int) -> tuple[list[list[int]], list[list[int]]]:
    """
    Splits the key
    """
    words = [raw_key_bits[i*n:(i+1)*n] for i in range(m)]
    k = [words[0]]
    l = words[1:]
    return l, k

def split_plaintext(plaintext_bits: list[int], n: int) -> tuple[list[int], list[int]] | None:
    """
    Splits the plaintext
    """
    block_size = 2 * n

    if len(plaintext_bits) > block_size:
        print(f"  Plaintext too long: {len(plaintext_bits)} bits > {block_size} bits (2*n).")
        print(f"  Reduce your input to at most {block_size // 8} bytes.")
        return None

    if len(plaintext_bits) < block_size:
        padding = block_size - len(plaintext_bits)
        plaintext_bits = plaintext_bits + [0] * padding
        print(f"  Padded with {padding} zero bits to reach {block_size} bits.")

    x = plaintext_bits[:n]
    y = plaintext_bits[n:]
    return x, y

menu = {
    "1": "Encrypt",
    "2": "Decrypt",
    "0": "Quit",
}


def main():
    while True:
        launcher.clear_screen()
        tools.print_menu("SPECK Application", menu)

        try:
            choice = input("Choice: ").strip()

            if choice not in menu:
                print(f"Invalid choice: {choice}")
                input("Press enter to continue...")
                continue

            if choice == "0":
                print("Closing SPECK Application.")
                sys.exit(0)

            result = select_n_and_m()
            if result is None:
                input("Press enter to continue...")
                continue
            n, m = result

            raw_key_bits = tools.read_key((n*m)//4)
            if raw_key_bits is None:
                input("Press enter to continue...")
                continue

            l, k = split_key(raw_key_bits, n, m)

            raw_text = input(f"\n  Enter message (max {2*n//8} bytes): ")
            plaintext_bits = text_to_bit_array(raw_text)

            xy = split_plaintext(plaintext_bits, n)
            if xy is None:
                input("Press enter to continue...")
                continue
            x, y = xy

            if choice == "1":
                x_out, y_out = speck(n, m, x, y, l, k)
            else:
                x_out, y_out = inverse_speck(n, m, x, y, l, k)

            result_bits = x_out + y_out
            result_text = bit_array_to_text(result_bits)
            result_hex  = hex(int("".join(str(b) for b in result_bits), 2))

            print(f"\n  Text content: {result_text}")
            print(f"  Hex content:  {result_hex}")
            input("\nPress enter to continue...")

        except KeyboardInterrupt:
            print("\nClosing SPECK Application.")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
            input("Press enter to continue...")


if __name__ == "__main__":
    print("Program launched successfully")
    main()
