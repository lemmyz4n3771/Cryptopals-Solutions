from functools import reduce
from Crypto.Cipher import AES


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