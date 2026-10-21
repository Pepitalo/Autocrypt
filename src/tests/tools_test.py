from launcher import check
import tools

check("Array to 4 tuple", tools.array_to_4_tuple([1, 3, 4, 2]), (1, 3, 4, 2))
check("Char to bit array", tools.char_to_bit_array('a'), [0, 1, 1, 0, 0, 0, 0, 1])
check("Bit array to char", tools.bit_array_to_char([0, 1, 1, 0, 0, 0, 0, 1]), 'a')
check("Text to bit array", tools.text_to_bit_array("UwU"), [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1])
check("Bit array to text", tools.bit_array_to_text([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1]), "UwU")
check("Resize Key 1", tools.resize_key([1,3,2,4],5), [1,3,2,4,1])
check("Resize Key 2", tools.resize_key([1,3,2,4],3), [1,3,2])
check("Split bit array", tools.split_bit_array([1,3,2,4,5,7,6,8],4), [[1,3,2,4],[5,7,6,8]])
check("Array formatting, 0 padding", tools.array_formatting([1,4,7,6,3], 8), [1,4,7,6,3,0,0,0])
check("Array formatting, truncate", tools.array_formatting([1,4,7,6,3], 3), [1,4,7])
ror16_vectors = [
	(0x0001,  1, 0x8000),  # LSB wraps to MSB
	(0x8000,  1, 0x4000),  # MSB shifts right
	(0xABCD,  4, 0xDABC),  # nibble rotation: last 4 bits (1101) to front
	(0x1234,  0, 0x1234),  # identity: r=0
	(0x1234, 16, 0x1234),  # identity: full cycle
	(0xFFFF,  7, 0xFFFF),  # all-ones: invariant
	(0x0001, 15, 0x0002),  # ror15 == rol1
	]

for (val, r, expected) in ror16_vectors:
	check(f"ror16(0x{val:04X}, {r:2d})", tools.bit_array_to_int(tools.ror16(tools.int_to_bit_array(val, 16), r)), expected)
