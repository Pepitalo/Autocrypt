"""
AES-128 implementation.

AES_128(input,key): encrypt the input with the given key.
AES_128_decryption(output,key): decrypt the output with the given key.
one_round(s,w): one round encryption of AES.

AES_S_BOX: a dict[tuple->tuple] representing the S-box.
TODOLATER: (AES_linear_part: linear part of AES.)
"""


# Some "assert" are commented in order to be have less complexity.
# Feel free to uncomment them, but please don't delete them.


## Conventions:

# key: 128 bits array [k0,k1,...,k127]
    # a key can also be represented as 16 bytes [a0,...a15]
# byte: 8 bits array [b7,b6,b5,b4,b3,b2,b1,b0]
    # make sure to use the good order in computations
    # a byte can also be represented in hexadecimal with 2 digits 0xlr
    # where l and r are the hexadecimal representations of [b7,b6,b5,b4] and [b3,b2,b1,b0]
# state: matrix of 4 by 4 bytes
# word: 4 bytes


## AES-128 implementation


from tools import int_to_bit_array, bit_array_to_int, xor_arrays, split_bit_array, text_to_bit_array, bit_array_to_text
import launcher
import tools


def AES_128(input:list[int],key:list[int]):
    """
    input, key: bit arrays
    output: the encrypted bit array
    """
    return cipher(input,10,key_expansion(key))


def AES_128_decryption(output:list[int],key:list[int]):
    """
    output, key: bit arrays
    ouput of the function: the decrypted bit array
    """
    return inv_cipher(output,10,key_expansion(key))


## Key expansion


r_con = [[[0]*7+[1],[0]*8,[0]*8,[0]*8],
        [[0]*6+[1,0],[0]*8,[0]*8,[0]*8],
        [[0]*5+[1,0,0],[0]*8,[0]*8,[0]*8],
        [[0]*4+[1,0,0,0],[0]*8,[0]*8,[0]*8],
        [[0,0,0,1]+[0]*4,[0]*8,[0]*8,[0]*8],
        [[0,0,1,0]+[0]*4,[0]*8,[0]*8,[0]*8],
        [[0,1,0,0]+[0]*4,[0]*8,[0]*8,[0]*8],
        [[1,0,0,0]+[0]*4,[0]*8,[0]*8,[0]*8],
        [[0,0,0,1,1,0,1,1],[0]*8,[0]*8,[0]*8],
        [[0,0,1,1,0,1,1,0],[0]*8,[0]*8,[0]*8]]


def key_expansion(key:list[int])->list[list[list[int]]]:
    """
    Input: the key as a 128-bits array
    Output: the expanded key as a sequence of 4*(Nr+1)=44 words
    """
    key_bis = split_bit_array(key,8)
    Nk = 4
    Nr = 10
    w = [[[0]*8 for _ in range(4)] for _ in range(4*(Nr+1))]
    i = 0
    while i <= Nk-1:
        w[i] = key_bis[4*i:4*(i+1)]
        i += 1
    while i <= 4*Nr+3:
        temp = w[i-1].copy()
        if i%Nk==0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp = xor_words(temp,r_con[i//Nk-1])   # -1 because r_con starts at 0 but i//Nk starts at 1
        elif Nk>6 and i%Nk==4:
            temp = sub_word(temp)
        w[i] = xor_words(w[i-Nk],temp)
        i += 1
    return w


def rot_word(a:list[list[int]])->list[list[int]]:
    """
    Input: a word
    Output: a word
    """
    #assert(len(a)==4)
    #for i in range(4):
    #    assert(len(a[i])==8)
    a_bis = [[0]*8 for _ in range(4)]
    a_bis[:3] = a[1:]
    a_bis[3] = a[0]
    return a_bis


def sub_word(a:list[list[int]])->list[list[int]]:
    """
    Input: a word
    Output: a word
    """
    #assert(len(a)==4)
    #for i in range(4):
    #    assert(len(a[i])==8)
    a_bis = [[0]*8 for _ in range(4)]
    for i in range(4):
        a_bis[i] = s_box(a[i])
    return a_bis


def s_box(b:list[int])->list[int]:
    """
    Input: a byte
    Output: a byte
    """
    #assert(len(b)==8)
    c = [1,1,0,0,0,1,1,0]
    if b == [0,0,0,0,0,0,0,0]:
        b_bis = [0,0,0,0,0,0,0,0]
    else:
        b_bis = inverse(b)
        b_bis.reverse() # because of the convention for bytes
    M = [[1,0,0,0,1,1,1,1],
        [1,1,0,0,0,1,1,1],
        [1,1,1,0,0,0,1,1],
        [1,1,1,1,0,0,0,1],
        [1,1,1,1,1,0,0,0],
        [0,1,1,1,1,1,0,0],
        [0,0,1,1,1,1,1,0],
        [0,0,0,1,1,1,1,1]]
    b_ter = addition(bit_matrix_vector_product(M,b_bis),c)
    b_ter.reverse() # because of the convention for bytes
    return b_ter


## Cipher


def cipher(input:list[int],Nr:int,w:list[list[int]]):
    """
    Input: a sequence of 16 bytes
            the number of rounds (10)
            a sequence of 4*(Nr+1)=44 words for the key schedule
    Output: a sequence of 16 bytes
    """
    assert(len(input)==16)
    for i in range(16):
        assert(len(input[i])==8)
    assert(len(w)==4*(Nr+1))    # w should be an array of 4*(Nr+1) words
    for i in range(4*(Nr+1)):
        assert(len(w[i])==4)
        for j in range(len(w[i])):
            assert(len(w[i][j])==8)
    s = [[[0]*8 for _ in range(4)] for _ in range(4)]   # state: 2-dimensional array of bytes
    for r in range(4):
        for c in range(4):
            s[r][c] = input[r+4*c]
    s = add_round_key(s,w[0:4])
    for round in range(1,Nr):
        s = one_round(s,w[4*round:4*round+4])
    s = sub_bytes(s)
    s = shift_rows(s)
    s = add_round_key(s,w[4*Nr:4*Nr+4])
    output = [[0]*8 for _ in range(16)]
    for r in range(4):
        for c in range(4):
            output[r+4*c] = s[r][c]
    return output


def one_round(s:list[list[int]],w:list[list[int]])->list[list[int]]:
    """
    Input: a state
            a sequence 4 words
    Output: nothing (in place))
    """
    assert(len(s)==4)
    for i in range(4):
        assert(len(s[i])==4)
        for j in range(4):
            assert(len(s[i][j])==8)
    for i in range(len(w)):
        assert(len(w[i])==4)
        for j in range(4):
            assert(len(w[i][j])==8)
    s_bis = s.copy()
    s_bis = sub_bytes(s_bis)
    s_bis = shift_rows(s_bis)
    s_bis = mix_columns(s_bis)
    s_bis = add_round_key(s_bis,w)
    return s_bis


def add_round_key(s:list[list[int]],w:list[list[int]])->list[list[int]]:
    """
    Input: a state
            a sequence of 4 words
    Output: a state
    """
    #assert(len(s)==4)
    #assert(len(w)==4)
    #for i in range(4):
    #    assert(len(s[i])==4)
    #    assert(len(w[i])==4)
    #    for j in range(4):
    #        assert(len(s[i][j])==8)
    #        assert(len(w[i][j])==8)
    s_bis = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for c in range(4):
        s_c = [[0]*8 for _ in range(4)]
        for r in range(4):
            s_c[r] = s[r][c].copy()
        s_c_bis = xor_words(s_c,w[c])
        for r in range(4):
            s_bis[r][c] = s_c_bis[r].copy()
    return s_bis


def sub_bytes(s:list[list[list[int]]])->list[list[list[int]]]:
    """
    Input: a state
    Output: a state
    """
    #assert(len(s)==4)
    #for r in range(4):
    #    assert(len(s[r])==4)
    #    for c in range(4):
    #        assert(len(s[r][c])==8)
    s_bis = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            s_bis[r][c] = s_box(s[r][c])
    return s_bis


def shift_rows(s:list[list[list[int]]])->list[list[list[int]]]:
    """
    Input: a state
    Output: a state
    """
    s_bis = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            s_bis[r][c] = s[r][(c+r)%4]
    return s_bis


def mix_columns(s:list[list[list[int]]])->list[list[list[int]]]:
    """
    Input: a state
    Output: a state
    """
    M = [[[0]*6+[1,0],[0]*6+[1,1],[0]*6+[0,1],[0]*6+[0,1]],
        [[0]*6+[0,1],[0]*6+[1,0],[0]*6+[1,1],[0]*6+[0,1]],
        [[0]*6+[0,1],[0]*6+[0,1],[0]*6+[1,0],[0]*6+[1,1]],
        [[0]*6+[1,1],[0]*6+[0,1],[0]*6+[0,1],[0]*6+[1,0]]]
    s_bis = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for c in range(4):
        s_c = [[0]*8 for _ in range(4)]
        for r in range(4):
            s_c[r] = s[r][c]
        s_c_bis = words_matrix_vector_product(M,s_c)
        for r in range(4):
            s_bis[r][c] = s_c_bis[r]
    return s_bis


## Inversion cipher


def inv_cipher(input,Nr,w):
    """
    Input: a sequence of 16 bytes
            the number of rounds (10)
            a sequence of 4*(Nr+1)=44 words for the key schedule
    Output: a sequence of 16 bytes
    """
    s = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            s[r][c] = input[r+4*c]
    s = add_round_key(s,w[4*Nr:4*(Nr+1)])
    for round in range(Nr-1,0,-1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s,w[4*round:4*(round+1)])
        s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = add_round_key(s,w[0:4])
    output = [[0]*8 for _ in range(16)]
    for r in range(4):
        for c in range(4):
            output[r+4*c] = s[r][c]
    return output


def inv_shift_rows(s:list[list[list[int]]])->list[list[list[int]]]:
    """
    Input: a state
    Output: a state
    """
    s_bis = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            s_bis[r][c] = s[r][(c-r)%4]
    return s_bis


def inv_sub_bytes(s:list[list[list[int]]])->list[list[list[int]]]:
    """
    Input: a state
    Output: a state
    """
    #assert(len(s)==4)
    #for r in range(4):
    #    assert(len(s[r])==4)
    #    for c in range(4):
    #        assert(len(s[r][c])==8)
    s_bis = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            s_bis[r][c] = inv_s_box(s[r][c])
    return s_bis


def inv_s_box(b:list[int])->list[int]:
    """
    Input: a byte
    Output: a byte
    """
    M = [['52','09','6a','d5','30','36','a5','38','bf','40','a3','9e','81','f3','d7','fb'],
        ['7c','e3','39','82','9b','2f','ff','87','34','8e','43','44','c4','de','e9','cb'],
        ['54','7b','94','32','a6','c2','23','3d','ee','4c','95','0b','42','fa','c3','4e'],
        ['08','2e','a1','66','28','d9','24','b2','76','5b','a2','49','6d','8b','d1','25'],
        ['72','f8','f6','64','86','68','98','16','d4','a4','5c','cc','5d','65','b6','92'],
        ['6c','70','48','50','fd','ed','b9','da','5e','15','46','57','a7','8d','9d','84'],
        ['90','d8','ab','00','8c','bc','d3','0a','f7','e4','58','05','b8','b3','45','06'],
        ['d0','2c','1e','8f','ca','3f','0f','02','c1','af','bd','03','01','13','8a','6b'],
        ['3a','91','11','41','4f','67','dc','ea','97','f2','cf','ce','f0','b4','e6','73'],
        ['96','ac','74','22','e7','ad','35','85','e2','f9','37','e8','1c','75','df','6e'],
        ['47','f1','1a','71','1d','29','c5','89','6f','b7','62','0e','aa','18','be','1b'],
        ['fc','56','3e','4b','c6','d2','79','20','9a','db','c0','fe','78','cd','5a','f4'],
        ['1f','dd','a8','33','88','07','c7','31','b1','12','10','59','27','80','ec','5f'],
        ['60','51','7f','a9','19','b5','4a','0d','2d','e5','7a','9f','93','c9','9c','ef'],
        ['a0','e0','3b','4d','ae','2a','f5','b0','c8','eb','bb','3c','83','53','99','61'],
        ['17','2b','04','7e','ba','77','d6','26','e1','69','14','63','55','21','0c','7d']]
    for i in range(16):
        for j in range(16):
            M[i][j] = int_to_bit_array(int('0x'+M[i][j][0],16),4)+int_to_bit_array(int('0x'+M[i][j][1],16),4)
    x = bit_array_to_int(b[:4])
    y = bit_array_to_int(b[4:])
    return M[x][y]


def inv_mix_columns(s:list[list[list[int]]])->list[list[list[int]]]:
    """
    Input: a state
    Output: a state
    """
    M = [[[0]*4+[1,1,1,0],[0]*4+[1,0,1,1],[0]*4+[1,1,0,1],[0]*4+[1,0,0,1]],
        [[0]*4+[1,0,0,1],[0]*4+[1,1,1,0],[0]*4+[1,0,1,1],[0]*4+[1,1,0,1]],
        [[0]*4+[1,1,0,1],[0]*4+[1,0,0,1],[0]*4+[1,1,1,0],[0]*4+[1,0,1,1]],
        [[0]*4+[1,0,1,1],[0]*4+[1,1,0,1],[0]*4+[1,0,0,1],[0]*4+[1,1,1,0]]]
    s_bis = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for c in range(4):
        s_c = [[0]*8 for _ in range(4)]
        for r in range(4):
            s_c[r] = s[r][c]
        s_c_bis = words_matrix_vector_product(M,s_c)
        for r in range(4):
            s_bis[r][c] = s_c_bis[r]
    return s_bis


## Some tools


def xor_words(w1:list[list[int]],w2:list[list[int]])->list[list[int]]:
    """
    Input: 2 words
    Output: the resulting word after xoring each respective bytes
    """
    #assert(len(w1)==4)
    #assert(len(w2)==4)
    #for i in range(4):
    #    assert(len(w1[i])==8)
    #    assert(len(w2[i])==8)
    w = [[0]*8 for _ in range(4)]
    for i in range(4):
        for j in range(8):
            w[i][j] = w1[i][j]^w2[i][j]
    return w


def bit_matrix_vector_product(M:list[list[int]],x:list[int])->list[int]:
    """
    Input: a square bit-matrix and a bit-array of same dimension
    Output: the bit-array corresponding to their product
    """
    #for i in range(len(M)):
    #    assert(len(M)==len(M[i]))
    #assert(len(M)==len(x))
    y = [0] * len(x)
    for i in range(len(x)):
        y[i] = 0
        for j in range(len(x)):
            y[i] = (y[i] + M[i][j]*x[j]) % 2
    return y


def words_matrix_vector_product(M:list[list[list[int]]],s:list[list[int]])->list[list[int]]:
    """
    Input: a square bytes-matrix and a word
    Output: the word corresponding to their product
    """
    #assert(len(M)==4)
    #assert(len(s)==4)
    #for i in range(len(M)):
    #    assert(len(M[i])==4)
    #    assert(len(s[i])==8)
    #    for j in range(len(M[i])):
    #        assert(len(M[i][j])==8)
    s_bis = [[0]*8 for _ in range(4)]
    for i in range(len(s)):
        for j in range(len(s)):
            temp = multiplication(M[i][j],s[j])
            s_bis[i] = addition(s_bis[i],temp)
    return s_bis


## Operations in GF(2**8) (i.e. on bytes)


def addition(a:list[int],b:list[int])->list[int]:
    """
    Input: bit arrays of same length representing polynomials
    Output: their addition (also their substraction)
    """
    #assert(len(a)==len(b))
    c = [0] * len(a)
    for i in range(len(a)):
        if a[i]!=b[i]:
            c[i] = 1
    return c


def multiplication(b:list[int],c:list[int])->list[int]:
    """
    Input: bytes
    Output: their product in GF(256)
    """
    assert(len(b)==8)
    assert(len(c)==8)
    m = [0] * 7 + [1,0,0,0,1,1,0,1,1]
    b_bis = [0] * 8 + b
    c_bis = [0] * 8 + c
    result = [0] * 16
    for n in range(16):
        tmp = 0
        for k in range(n+1):
            tmp = (tmp + b_bis[15-k]*c_bis[15-(n-k)]) % 2
        result[15-n] = tmp
    return euclidian_division(result,m)


def inverse(b:list[int]): # This implementation may not be the most efficient.
    """
    Input: a byte
    Output: its inverse in GF(2**8)
    """
    results = [b]   # array of b**(2**i)
    for i in range(7):
        results.append(multiplication(results[i],results[i]))
    result = [0,0,0,0,0,0,0,1]
    for i in range(1,8):
        result = multiplication(result,results[i])
    return result


def degree(a:list[int])->int:
    """
    Input: a bit array representing a polynomial
    Output: its degree
    """
    i = 0
    for j in range(len(a)):
        if a[j] == 1:
            return len(a) - j - 1
    return -1


def euclidian_division(a:list[int],b:list[int])->list[int]:
    """
    Input: 2 16-bit arrays representing polynomials
    Output: a 8-bit array representing the rest of the euclidian division of a by b
    """
    #assert(degree(b)!=-1)
    #assert(len(a)==16)
    #assert(len(a)==16)
    p = a.copy()
    while degree(p) >= degree(b):
        d = b[degree(p)-degree(b):]+[0]*(degree(p)-degree(b))
        p = addition(p,d)
    return p[8:]


## Bonus: AES S-box


AES_S_BOX = {}

for i in range(256):
    b = int_to_bit_array(i, 8)
    AES_S_BOX[tuple(b)] = tuple(s_box(b))


## Bonus: Linear part


AES_BIT_PERM = {}


for r in range(4):
    for c in range(4):
        AES_BIT_PERM[r+4*c] = r + 4 * ((c+r)%4)


# Too complex to compile

def aes_linear_not_perm(input: tuple[int]) -> tuple[int]:
    """
    function version of the non linear part of AES
    """
    input = list(input)
    input_bis = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            input_bis[r][c] = input[8*(r+4*c):8*(r+4*c+1)]
    input_ter = mix_columns(input_bis)
    output = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            output[8*(r+4*c):8*(r+4*c+1)] = input_ter[r][c]
    return tuple(output)



"""
AES_LINEAR_NOT_PERM = {}


for i in range(2**256):
    input = int_to_bit_array(i,256)
    input_bis = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            input_bis[r][c] = input[8*(r+4*c):8*(r+4*c+1)]
    input_ter = mix_columns(input_bis)
    output = [[[0]*8 for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            output[8*(r+4*c):8*(r+4*c+1)] = input_ter[r][c]
    AES_LINEAR_NOT_PERM[tuple(input)] = tuple(output)
"""


## Launcher:


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
        tools.print_menu("AES Application", menu)

        try:
            choice = input("Choice: ").strip()

            if choice not in menu:
                print(f"Invalid choice: {choice}")
                input("Press enter to continue...")
                continue

            if choice == "0":
                print("Closing AES Application.")
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

            nb_of_rounds = 10
            if choice in ("2", "4"):
                raw_n = input("Number of rounds: ").strip()
                if not raw_n.isdigit() or int(raw_n) < 0:
                    print("Invalid number of rounds.")
                    input("Press enter to continue...")
                    continue
                nb_of_rounds = int(raw_n)

            with open(input_path, "r", encoding="utf-8") as f:
                full_bit_array = text_to_bit_array(f.read())

            padding_len = (128 - (len(full_bit_array) % 128)) % 128
            full_bit_array.extend([0] * padding_len)

            blocks = split_bit_array(full_bit_array, 128)
            result = []

            w = key_expansion(key)
            for block in blocks:
                block_bytes = split_bit_array(block, 8)
                if choice in ("1", "2"):
                    res_block = cipher(block_bytes, nb_of_rounds, w)
                else:
                    res_block = inv_cipher(block_bytes, nb_of_rounds, w)
                for byte in res_block:
                    result.extend(byte)

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
        except Exception as e:
            print(f"Error: {e}")
            input("Press enter to continue...")
        except KeyboardInterrupt:
            print("\nClosing AES Application.")
            sys.exit(0)


if __name__ == "__main__":
    print("Program launched successfully")
    main()

