# Write a function to generate a random AES key; that's just 16 random bytes
#  Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.
#
# The function should look like:
#
# encryption_oracle(your-input)
# => [MEANINGLESS JIBBER JABBER]
#  Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
#
# Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). 
# Use rand(2) to decide which to use.
#
# Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box 
# that might be encrypting ECB or CBC, tells you which one is happening. 

import random
from Crypto.Cipher import AES
from Crypto.Random import random
from os import urandom

class AESEncryptionOracle:
    def __init__(self, plaintext):
        self.key = urandom(AES.block_size)
        padded = self._pad(plaintext)
        chance = random.randint(0,1)
        if chance == 1:
            self.encryptionMethod = "ECB"
        else:
            self.encryptionMethod = "CBC"
        self.ciphertext = aesECBEncrypt(padded, self.key) if chance == 1 else aesCBCEncrypt(padded, self.key, urandom(AES.block_size))

    def _pad(self, binData):
        return urandom(random.randint(5,10)) + binData + urandom(random.randint(5,10))

def aesCBCEncrypt(data, key, iv):
    #  In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.
    #  The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext
    #  block" called the initialization vector, or IV. 
    #  Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt
    ciphertext = b''
    prev = iv

    for b in range(0, len(data), AES.block_size):
        padded = pkcs7Pad(data[b:b + AES.block_size], AES.block_size)
        xored = xor(padded, prev)
        encrypted = aesECBEncrypt(xored, key)
        ciphertext += encrypted
        prev = encrypted
    
    return ciphertext

def aesECBEncrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7Pad(data, AES.block_size))

def xor(data1, data2):
    return bytes([b1 ^ b2 for b1, b2 in zip(data1, data2)])

def pkcs7Pad(data, blockSize):
    if len(data) == blockSize:
        return data
    # in case len(data) is longer than blockSize, compute to next multiple of blockSize
    paddingByte = blockSize - len(data) % blockSize
    return data + (bytes([paddingByte]) * paddingByte)

def detectEncryption(ciphertext):
    dupes = findDupes(ciphertext)
    return "ECB" if dupes > 0 else "CBC"

def findDupes(ciphers):
    blocks = [ciphers[i:i + AES.block_size] for i in range(0, len(ciphers), AES.block_size)]
    dupes = len(blocks) - len(set(blocks))
    return dupes

for _ in range(100):

    oracle = AESEncryptionOracle(bytes([0])* 128)

    guess = detectEncryption(oracle.ciphertext)
    actual = oracle.encryptionMethod
    assert guess == actual