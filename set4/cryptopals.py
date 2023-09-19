from functools import reduce
from Crypto.Cipher import AES

CHARACTER_FREQ = {'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702, 
                  'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153, 
                  'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 
                  'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056, 
                  'u': 0.02758, 'v': 0.00978, 'w': 0.0236, 'x': 0.0015, 'y': 0.01974, 
                  'z': 0.00074, ' ': .18288} 
# sources: https://www.programming-algorithms.net/article/40379/Letter-frequency-English
# http://www.macfreek.nl/memory/Letter_Distribution

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