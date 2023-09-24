import struct
from Crypto.Random import get_random_bytes

# For pseudocode: https://en.wikipedia.org/wiki/SHA-1

def sha1(message: bytes, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0, setLength: int =None):
    # ml = message length in bits (always a multiple of the number of bits in a character)
    if setLength is None:
        ml = len(message) * 8
    else:
        ml = setLength * 8

    # Pre-processing:
    # append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
    message += bytes([0x80])

    # append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
    # is congruent to −64 ≡ 448 (mod 512)
    padLength = (448 // 8) - (len(message) % (512 // 8))
    padLength = (512 // 8) + padLength if padLength < 0 else padLength 
    message += bytes(padLength)

    # append ml, the original message length in bits, as a 64-bit big-endian integer. 
    # Thus, the total length is a multiple of 512 bits.
    message +=  ml.to_bytes(64 // 8, byteorder='big')


    if len(message) % 64 != 0:
        raise Exception("Message not a multiple of 512 bits")

    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for chunk in range(0, len(message), 64):
        # for each chunk
        ch = message[chunk : chunk + 64]
        # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        w = [int.from_bytes(ch[i : i + 4], "big") for i in range(0, len(ch), 4)]
        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
        # for i from 16 to 79
        for i in range(16, 80):
            # w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
            val = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            w.append(leftRotate(val, 1))
        # w should be 80
        assert len(w) == 80
        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        # Main loop:
        # for i from 0 to 79
        for i in range(80):
            # if 0 ≤ i ≤ 19 then
            if 0 <= i <= 19:
                # f = (b and c) or ((not b) and d)
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            # else if 20 ≤ i ≤ 39
            elif 20 <= i <= 39:
                # f = b xor c xor d
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            # else if 40 ≤ i ≤ 59
            elif 40 <= i <= 59:
                # f = (b and c) or (b and d) or (c and d) 
                f = ( b & c) | ( b & d ) | ( c & d)
                k = 0x8F1BBCDC
            # else if 60 ≤ i ≤ 79
            else:
                # f = b xor c xor d
                f = b ^ c ^ d
                k = 0xCA62C1D6
            # temp = (a leftrotate 5) + f + e + k + w[i]
            temp = (leftRotate(a, 5) + f + e + k + w[i]) & 0xffffffff
            e = d
            d = c
            c = leftRotate(b, 30)
            b = a
            a = temp
        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    # Produce the final hash value (big-endian) as a 160-bit number:
    finalHash = (struct.pack(">I", i) for i in [h0, h1, h2, h3, h4])
    finalHash = b''.join(finalHash)
    return finalHash

#  Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:
# SHA1(key || message)
def sha1MAC(message: bytes, key: bytes):
    return sha1(key + message)

def leftRotate(val: int, shiftLen: int):
    return ((val << shiftLen) & 0xffffffff) | (val >> (32 - shiftLen))


def main():
    key = get_random_bytes(16)
    message = b"Laputan Machine"
    hash = sha1MAC(message, key)
    print(hash)


if __name__ == "__main__":
    main()