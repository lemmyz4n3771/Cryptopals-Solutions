def fixedXOR(hex1, hex2):
    deci1 = int(hex1, 16)
    deci2 = int(hex2, 16)
    out = deci1 ^ deci2
    return hex(out)[2:]

input1 = b"1c0111001f010100061a024b53535009181c"
input2 = b'686974207468652062756c6c277320657965'

assert fixedXOR(input1, input2) == '746865206b696420646f6e277420706c6179'
print(fixedXOR(input1, input2))