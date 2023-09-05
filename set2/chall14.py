from base64 import b64decode 
import cryptopals
from Crypto.Cipher import AES
from os import urandom
from random import randint

class ECBOracle:
    def __init__(self, padding):
        self._key = urandom(AES.key_size[0])
        self._padding = padding
    
    def encrypt(self, data):
        return cryptopals.aesECBEncrypt(data + self._padding, self._key)

class ModdedECBOracle(ECBOracle):
    def __init__(self, secret):
        super().__init__(secret)
        self._prefix = urandom(randint(0,255))
    
    def encrypt(self, data):
        # AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
        return cryptopals.aesECBEncrypt(self._prefix + data + self._padding, self._key)


def byteByByteDecrypt(oracle: ModdedECBOracle):
    # get block size used
    blocksize = cryptopals.findBlocksize(oracle)
    # verify ECB mode being used
    assert cryptopals.detectECBMode(oracle.encrypt(bytes([0] * 4 * blocksize)))

    prefixLength = findPrefixLength(oracle, blocksize)

    secretLength = len(oracle.encrypt(b'')) - prefixLength

    secret = b''

    for i in range(secretLength):
        secret += nextByte(prefixLength, blocksize, secret, oracle)

    return secret

def nextByte(prefixLength, blocksize, decryptedSoFar, oracle: ModdedECBOracle):
    pinByteLength = (blocksize - prefixLength - (1 + len(decryptedSoFar))) % blocksize
    input = b'A' * pinByteLength
    crackingRegion = prefixLength + pinByteLength + len(decryptedSoFar) + 1

    ciphertext = oracle.encrypt(input)

    for i in range(256):
        attempt = oracle.encrypt(input + decryptedSoFar + bytes([i]))

        if attempt[:crackingRegion] == ciphertext[:crackingRegion]:
            return bytes([i])

    # padding error
    return b''



def hasConsecutiveBlocks(ciphertext, blocksize):
    for i in range(0, len(ciphertext) - 1, blocksize):
        if ciphertext[i:i + blocksize] == ciphertext[i + blocksize:i + blocksize * 2]:
            return True
    return False

def findPrefixLength(oracle: ModdedECBOracle, blocksize):
    cipher1 = oracle.encrypt(b'')
    cipher2 = oracle.encrypt(b'A')

    prefixLength = 0

    for i in range(0, len(cipher2), blocksize):
        if cipher1[i:i+blocksize] != cipher2[i:i+blocksize]:
            prefixLength = i
            break
    
    for i in range(blocksize):
        cipher = oracle.encrypt(bytes([0] * (2 * blocksize + i)))
        if hasConsecutiveBlocks(cipher, blocksize):
            return prefixLength + blocksize - i if i != 0 else prefixLength






def main():
    secretString = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                            "YnkK")
    oracle = ModdedECBOracle(secretString)

    print(byteByByteDecrypt(oracle))

if __name__ == "__main__":
    main()