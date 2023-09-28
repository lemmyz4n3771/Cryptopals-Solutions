from functools import reduce
from Crypto.Cipher import AES
import struct
from Crypto.Random import get_random_bytes

CHARACTER_FREQ = {'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702, 
                  'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153, 
                  'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 
                  'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056, 
                  'u': 0.02758, 'v': 0.00978, 'w': 0.0236, 'x': 0.0015, 'y': 0.01974, 
                  'z': 0.00074, ' ': .18288} 
# sources: https://www.programming-algorithms.net/article/40379/Letter-frequency-English
# http://www.macfreek.nl/memory/Letter_Distribution

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

# HMAC pseudocode: https://en.wikipedia.org/wiki/HMAC
# sha1 hmac implememtation
def hmac(key: bytes, message: bytes, hash_func: callable = sha1, blocksize: int = 64):
    # // Compute the block sized key
    key = computeBlockSizedKey(key)

    # o_key_pad ← block_sized_key xor [0x5c blockSize]   // Outer padded key
    o_key_pad = xorAll((key, bytes([0x5c] * blocksize)))
    # i_key_pad ← block_sized_key xor [0x36 blockSize]   // Inner padded key
    i_key_pad = xorAll((key, bytes([0x36] * blocksize)))

    # return  hash(o_key_pad ∥ hash(i_key_pad ∥ message))
    return hash_func(o_key_pad + hash_func(i_key_pad + message))

def computeBlockSizedKey(key: bytes, blocksize: int = 64):
    if len(key) > blocksize:
        key = sha1(key)
    if len(key) < 64:
        key += bytes([0] * (blocksize - len(key)))
    return key

def leftRotate(val: int, shiftLen: int):
    return ((val << shiftLen) & 0xffffffff) | (val >> (32 - shiftLen))

def aesECBDecrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7Unpad(cipher.decrypt(data), AES.block_size)

def xorAll(input: tuple[bytes, ...]) -> bytes:
    # Check validity of input
    if len(set(map(len, input))) != 1:
        raise Exception("Byte length not equal for at least one input")

    # Convert to int to XOR easily
    asInt = map(lambda x: int.from_bytes(x, "big"), input)
    xored= reduce(lambda x, y: x ^ y, asInt)
    return xored.to_bytes(len(input[0]), "big")

def pkcs7Pad(data: bytes, blockSize: int) -> bytes:
    if len(data) == blockSize:
        return data
    # in case len(data) is longer than blockSize, compute to next multiple of blockSize
    paddingByte = blockSize - (len(data) % blockSize)
    return data + bytes([paddingByte] * paddingByte)


def pkcs7Unpad(data: bytes, blocksize: int) -> bytes:
    # Check validity of input
    if len(data) % blocksize != 0:
        raise Exception(f"Data (length: {len(data)}) is not a multiple of blocksize({blocksize})")
    for i in range(blocksize, 0, -1):
        lastBlock = data[-i:]
        paddingValue= set(lastBlock)
        if len(paddingValue) == 1 and paddingValue.pop() == i:
            return data[:-i]
    # ValueError will not halt execution
    raise ValueError("No padding")


def aesCBCEncrypt(plaintext: bytes, key: bytes, iv: bytes = bytes(AES.block_size), setPadding=True) -> bytes:
    if setPadding:
        plaintext = pkcs7Pad(plaintext, blockSize=AES.block_size)

    if len(iv) != AES.block_size:
        raise Exception(f"IV not equal to blocksize {AES.block_size}")
    if len(plaintext) % AES.block_size != 0:
        raise Exception(f"Plaintext must be a multiple of block size")

    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    ciphertext = b''
    for i in range(0, len(plaintext), AES.block_size):
        curBlock = plaintext[i:i+AES.block_size]
        curBlock = xorAll((curBlock, prev))
        curBlock= cipher.encrypt(curBlock)
        ciphertext += curBlock

        prev = curBlock

    return ciphertext

def aesCBCDecrypt(ciphertext: bytes, key: bytes, iv: bytes = bytes(AES.block_size), unpad=False) -> bytes:
    if len(iv) != AES.block_size:
        raise Exception("IV not equal blocksize")
    if len(ciphertext) % AES.block_size != 0:
        raise Exception(f"Ciphertext (length: {len(ciphertext)} not a multiple of blocksize ({AES.block_size})")

    cipher = AES.new(key, AES.MODE_ECB)

    prev = iv
    plaintext = bytes()
    for i in range(0, len(ciphertext), AES.block_size):
        curBlock = ciphertext[i:i+AES.block_size]
        plaintext_block = cipher.decrypt(curBlock)
        plaintext_block = xorAll((plaintext_block, prev))
        plaintext += plaintext_block

        prev = curBlock

    if unpad:
        plaintext = pkcs7Unpad(plaintext, AES.block_size)

    return plaintext

def brute(input):
    results = []

    for x in range(256):
        plaintext = singleByteXOR(input, x)
        stats = {
            'key': x,
            'result': plaintext,
            'score': computeScore(plaintext)
        }
        results.append(stats)
    out = sorted(results, key=(lambda x: x['score']), reverse=True)[0]
    return out["key"]

def singleByteXOR(inputAsBytes, key):
    out = b''
    for b in inputAsBytes:
        out += bytes([b ^ key])
    return out

def computeScore(input):
    sum = 0
    for i in input:
        sum += CHARACTER_FREQ.get(chr(i).lower(), 0)
    return sum