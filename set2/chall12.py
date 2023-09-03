from base64 import b64decode
from os import urandom
from Crypto.Cipher import AES

class ECBOracle:
    def __init__(self, padding):
        self._key = urandom(AES.key_size[0])
        self._padding = padding
    
    def encrypt(self, data):
        return aesECBEncrypt(data + self._padding, self._key)
        

def ECBDecrypt(oracle: ECBOracle):
    # Discover block size
    blocksize = findBlocksize(oracle)

    # Detect that the function is using ECB
    ciphertext = oracle.encrypt(b'\x00' * 64)
    assert detectECBMode(ciphertext) != 0

    # Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA")
    bytesToDecrypt = len(oracle.encrypt(b''))
    b64padding = b''

    for i in range(bytesToDecrypt):
        b64padding += nextByte(blocksize, b64padding, oracle)
    
    return b64padding

def nextByte(blocksize, decryptedSoFar, oracle: ECBOracle):
    fillLength = (blocksize - (1 + len(decryptedSoFar) % blocksize))
    fillPadding = b'A' * fillLength

    # should always equal block size
    bytesToCompare = fillLength + len(decryptedSoFar) + 1

    expectedEncryption = oracle.encrypt(fillPadding)
#    print(f"Fill length: {fillLength}" )
#    print(b"Fill padding: " + fillPadding)
#    print(f"Bytes to compare: {bytesToCompare}")

    for i in range(256):
        attemptedCipher = oracle.encrypt(fillPadding + decryptedSoFar + bytes([i]))
#        print(b"Exptected: " + expectedEncryption[:bytesToCompare])
#        print(b"Attempted: " + attemptedCipher[:bytesToCompare])
#        input()
        if expectedEncryption[:bytesToCompare] == attemptedCipher[:bytesToCompare]:
            return bytes([i])
    
    # padding error
    return b''


def findBlocksize(oracle):
    # Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), 
    # then "AA", then "AAA" and so on. Discover the block size of the cipher.

    message = b''
    ciphertext = oracle.encrypt(message)
    initialBlocksize = len(ciphertext)
    nextBlocksize = initialBlocksize

    while nextBlocksize == initialBlocksize:
        message += b'A'
        ciphertext = oracle.encrypt(message)
        nextBlocksize = len(ciphertext)
    
    return nextBlocksize - initialBlocksize

def detectECBMode(ciphertext):
    return findECBDupes(ciphertext) > 0

def findECBDupes(ciphers):
    blocks = [ciphers[i:i + AES.block_size] for i in range(0, len(ciphers), AES.block_size)]
    dupes = len(blocks) - len(set(blocks))
    return dupes

def xor(data1, data2):
    return bytes([b1 ^ b2 for b1, b2 in zip(data1, data2)])

def aesECBEncrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7Pad(data, AES.block_size))

def pkcs7Pad(data, blockSize):
    if len(data) == blockSize:
        return data
    # in case len(data) is longer than blockSize, compute to next multiple of blockSize
    paddingByte = blockSize - len(data) % blockSize
    return data + (bytes([paddingByte]) * paddingByte)

def isPKCS7Padded(data):
    lastByte = data[-1]
    padding = data[-lastByte:]
    if lastByte > len(padding):
        return False
    return all([lastByte == padding[byte] for byte in range(len(padding))])

def pkcs7Unpad(data):
    if not isPKCS7Padded(data):
        return data
    padLength = data[len(data)-1]
    return data[:-padLength]

def main():

    secretString = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                            "YnkK")
    
    oracle = ECBOracle(secretString)

    b64secret = ECBDecrypt(oracle)
    print(b64secret)



if __name__ == "__main__":
    main()