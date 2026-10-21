"""
Code of the Alzette cipher.

alzette_one_round_encryption(x,y): encrypt the (x,y) bit array.
alzette_one_round_decryption(x,y): decrypt the (x,y) bit array.

ALZETTE_S_BOX: a dict representing Alzette as a S-box.
WARNING: the S-box is way too complex to be used as such.

There is no permutation in Alzette, it behaves as a 64 bit S-box.
"""


from tools import xor_two_arrays, int_to_bit_array, text_to_bit_array, split_bit_array, bit_array_to_text
import launcher
import tools

def alzette_one_round_encryption(x: list[int], y: list[int], c: list[int] = int_to_bit_array(0xb7e15162, 32)) -> tuple[list[int]]:
    """
    x and y: arrays of 32 bits
    c: round constant of 32 bits
    One round of encryption of x and y.
    """
    # actually, we might use several different c
    # maybe alterning each of them
    # see the paper on Alzette for more details.
    x_tmp, y_tmp = x.copy(), y.copy()
    x_tmp = addition(32, x_tmp, S(1, y_tmp))
    y_tmp = xor(y_tmp, S(8, x_tmp))
    x_tmp = xor(x_tmp, c)
    x_tmp = addition(32, x_tmp, S(15, y_tmp))
    y_tmp = xor(y_tmp, S(15, x_tmp))
    x_tmp = xor(x_tmp, c)
    x_tmp = addition(32, x_tmp, y_tmp)
    y_tmp = xor(y_tmp, S(1, x_tmp))
    x_tmp = xor(x_tmp, c)
    x_tmp = addition(32, x_tmp, S(8, y_tmp))
    y_tmp = xor(y_tmp, S(16, x_tmp))
    x_tmp = xor(x_tmp, c)
    return x_tmp, y_tmp


def alzette_one_round_decryption(x: list[int], y: list[int], c: list[int] = int_to_bit_array(0xb7e15162, 32)) -> tuple[list[int]]:
    """
    x and y: arrays of 32 bits
    c: round constant of 32 bits
    One round of decryption of x and y.
    """
    # same remark as above for c
    x_tmp, y_tmp = x.copy(), y.copy()
    x_tmp = xor(x_tmp, c)
    y_tmp = xor(y_tmp, S(16, x_tmp))
    x_tmp = substraction(32, x_tmp, S(8, y_tmp))
    x_tmp = xor(x_tmp, c)
    y_tmp = xor(y_tmp, S(1, x_tmp))
    x_tmp = substraction(32, x_tmp, y_tmp)
    x_tmp = xor(x_tmp, c)
    y_tmp = xor(y_tmp, S(15, x_tmp))
    x_tmp = substraction(32, x_tmp, S(15, y_tmp))
    x_tmp = xor(x_tmp, c)
    y_tmp = xor(y_tmp, S(8, x_tmp))
    x_tmp = substraction(32, x_tmp, S(1, y_tmp))
    return x_tmp, y_tmp


## Tools: the same as for Speck


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


## Bonus: Alzette as a S-box


# it doesn't compile because of too much complexity.
"""
ALZETTE_S_BOX = {}
for i in range(2**64):
    xy = int_to_bit_array(i, 64)
    x = xy[:32]
    y = xy[32:]
    output = alzette_one_round_encryption(x,y)
    ALZETTE_S_BOX[tuple(xy)] = tuple(output[0]+output[1])
"""
menu = {
    "1": "Encrypt 1 round",
    "2": "Encrypt N rounds",
    "3": "Decrypt 1 round",
    "4": "Decrypt N rounds",
    "0": "Quit",
}


def _run_alzette(block: list[int], nb_of_rounds: int, encrypt: bool) -> list[int]:
    """simply applies alzette recursively on a 64 bit blovk"""
    x, y = block[:32], block[32:]
    if encrypt:
        for _ in range(nb_of_rounds):
            x, y = alzette_one_round_encryption(x, y)
    else:
        for _ in range(nb_of_rounds):
            x, y = alzette_one_round_decryption(x, y)
    return x + y


def main():
    os.makedirs("testfiles", exist_ok=True)

    while True:
        launcher.clear_screen()
        tools.print_menu("ALZETTE Application", menu)

        try:
            choice = input("Choice: ").strip()

            if choice not in menu:
                print(f"Invalid choice: {choice}")
                input("Press enter to continue...")
                continue

            if choice == "0":
                print("Closing ALZETTE Application.")
                sys.exit(0)

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

            nb_of_rounds = 1
            if choice in ("2", "4"):
                raw_n = input("Number of rounds: ").strip()
                if not raw_n.isdigit() or int(raw_n) <= 0:
                    print("Invalid number of rounds.")
                    input("Press enter to continue...")
                    continue
                nb_of_rounds = int(raw_n)

            with open(input_path, "r", encoding="utf-8") as f:
                full_bit_array = text_to_bit_array(f.read())

            # Alzette works on blocs of 64 bits so we padd acordingly
            padding_len = (64 - (len(full_bit_array) % 64)) % 64
            full_bit_array.extend([0] * padding_len)

            blocks = split_bit_array(full_bit_array, 64)
            result = []

            encrypt = choice in ("1", "2")
            for block in blocks:
                result.extend(_run_alzette(block, nb_of_rounds, encrypt))

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(bit_array_to_text(result))

            print(f"Result written to: {output_path}")
            print("\n" + "-" * 20 + " FILE CONTENT " + "-" * 20)
            os.system(f"cat '{output_path}'")
            print("\n" + "-" * 54 + "\n")
            input("Press enter to continue...")

        except FileNotFoundError as e:
            print(f"File not found: {e}")
            input("Press enter to continue...")
        except KeyboardInterrupt:
            print("\nClosing ALZETTE Application.")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
            input("Press enter to continue...")


if __name__ == "__main__":
    print("Program launched successfully")
    main()
