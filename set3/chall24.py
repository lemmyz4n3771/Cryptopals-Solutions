from chall21 import MT19937
import cryptopals
import math
from Crypto.Random import get_random_bytes
from random import randint
import time

# Create stream cipher using MT19937
class MT19937Cipher:
    def __init__(self, seed: int):
        # 16-bit seed
#        if seed > 2**16 -1:
#            raise ValueError("Seed exceeds 16-bits")
        
        self.seed = seed
        self.rng = MT19937(seed)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        keystream = self.makeKeystream(plaintext)
        return cryptopals.xorAll((plaintext, keystream))
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        # Because this is XOR, encryption is the same as decryption, but with ciphertext 
        # instead of plaintext
        return self.encrypt(ciphertext)
    
    def makeKeystream(self, plaintext: bytes) -> bytes:
        # MT19937 generates 32-bit values or 4-byte values
        # Max iterations will be the upper of len(plaintext) / 4
        maxIter = math.ceil(len(plaintext) / 4)
        generator = (i.to_bytes(4, byteorder='little') for i in MT19937(seed=self.seed, iterations=maxIter))
        keystream = b''.join(generator)
        return keystream[:len(plaintext)]

def crackMT19937Cipher(ciphertext: bytes, knownPlaintext: bytes) -> bytes:
    # Note: this function only works for 16 bit seed
    # 2**16 is a small keyspace. Just brute-force all the values and see if the plaintext is
    # in the decryption
    for s in range(2**16):
        tryMe = MT19937Cipher(s).decrypt(ciphertext=ciphertext)
        if knownPlaintext in tryMe:
            return s

def isProductOfMT19937(ciphertext: bytes, knownPlaintext: bytes) -> bool:
    curTime = int(time.time())    

    # Brute force within last 10 minutes of current time
    for s in range(curTime - 6000, curTime):
        tryMe = MT19937Cipher(s).decrypt(ciphertext)
        if knownPlaintext in tryMe:
            return True
    return False


def main():
    cipherMT= MT19937Cipher(1)
    # Confirm encryption and decryption works
    enc = cipherMT.encrypt(b"Lemmy")
    print(enc)
    print(cipherMT.decrypt(enc))

    # Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) 
    # prefixed by a random number of random characters

    seed = randint(0, 2 **16 -1)
    curTime= int(time.time())
    cipherMT= MT19937Cipher(seed)
    prefix = get_random_bytes(randint(0, 100))
    plaintext = b'A' * 14
    ciphertext = cipherMT.encrypt(prefix + plaintext)

    origSeed = crackMT19937Cipher(ciphertext, plaintext)
    assert origSeed == seed
    print("Found original seed")

    # Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.
    cipherMT = MT19937Cipher(curTime)
    prefix = get_random_bytes(randint(0, 100))
    plaintext = b";password_reset=true"
    passwordResetToken = cipherMT.encrypt(prefix + plaintext)
    
    assert isProductOfMT19937(passwordResetToken, plaintext)
    print("Password token is MT19937 generated with current time")


if __name__ == "__main__":
    main()

