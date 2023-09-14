from base64 import b64decode
import math
import cryptopals
from Crypto.Random import get_random_bytes
from os import urandom
from Crypto.Cipher import AES

class AesCtrMode:
    def __init__(self, key: bytes, nonce: bytes, byteorder="little"):
        if byteorder not in ["big", "little"]:
            raise ValueError("byteorder must be set to big or little endian")
        
        if nonce is None:
            self.nonce = urandom(8)
        else:
            self.nonce = nonce
        
        self.key = key
        self.byteorder = byteorder
        self.cipher = AES.new(self.key, AES.MODE_ECB)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        # Encryption is XOR'd against the plaintext
        keyStream = self.makeKeyStream(len(plaintext))
        ciphertext = cryptopals.xorAll((plaintext,keyStream))
        return ciphertext

    def encrypt(self, plaintext: bytes) -> bytes:
        # Encryption is XOR'd against the plaintext
        keyStream = self.makeKeyStream(len(plaintext))
        ciphertext = cryptopals.xorAll((plaintext,keyStream))
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Decryption is identical to encryption: Generate the same keystream, XOR, and recover the plaintext. 
        keyStream = self.makeKeyStream(len(ciphertext))
        plaintext = cryptopals.xorAll((ciphertext, keyStream))
        return plaintext

    # Create a keystream that works for either big or little endian
    def makeKeyStream(self, inputLength: int) -> bytes:
        # CTR mode encrypts a running counter, producing a 16 byte block of keystream
        keyStream = b''
        for counter in range(math.ceil(inputLength / AES.block_size)):
            # concat nonce and counter
            concatNonceCounter = self.nonce + counter.to_bytes(AES.block_size // 2, byteorder=self.byteorder)
            keyStream += self.cipher.encrypt(concatNonceCounter)
        keyStream = keyStream[:inputLength]
        return keyStream


def shiftBlocks(data: bytes, keySize: int):
    # This method will break up a data stream into blocks of size keySize, since ultimately this is an XOR
    # operation and keySize must equal blocksize
    return [data[shift::keySize] for shift in range(keySize)]

def breakAESCTRStatistically(streams: list) -> bytes:
    # To exploit this: take your collection of ciphertexts and truncate them 
    # to a common length (the length of the smallest ciphertext will work). 
    minLength = min(len(x) for x in streams)
    ciphertext = b''.join([stream[:minLength] for stream in streams])
    # Solve the resulting concatenation of ciphertexts as if for repeating-key XOR, 
    # with a key size of the length of the ciphertext you XOR'd. 
    shifted = shiftBlocks(ciphertext, minLength)
    keystream = b''
    for s in shifted:
        keystream += bytes([cryptopals.brute(s)])
    return keystream

def main():
    with open("20.txt", 'r') as f:
        contents = f.readlines()
    data = [b64decode(x) for x in contents]

    key = get_random_bytes(AES.block_size)
    cipher = AesCtrMode(key, nonce=bytes(8), byteorder="little")
    encrypted = [cipher.encrypt(d) for d in data]

    keystream = breakAESCTRStatistically(encrypted)

    for e in encrypted:
        truncated = e[:len(keystream)]
        decrypted = cryptopals.xorAll((truncated, keystream))
        print(decrypted)

if __name__ == "__main__":
    main()