def toBase64(hex_data):
    b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    decimal = int(hex_data, base=16)
    b64 = ""
    while decimal > 0:
        r = decimal % 64
        b64 = b64Chars[r] + b64
        decimal //= 64
    return b64

hex = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
assert toBase64(hex) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"