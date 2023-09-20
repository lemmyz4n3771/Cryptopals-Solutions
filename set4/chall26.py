from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from os import urandom
import cryptopals
import math

class Oracle:
    def __init__(self):
        self.key = get_random_bytes(AES.block_size)
        self.ctr = AesCtrMode(self.key, nonce=None, byteorder="little")
        self._prefix = b"comment1=cooking%20MCs;userdata="
        self._suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    
    def encrypt(self, plaintext: bytes) -> bytes:
        data = plaintext.replace(b';', b'').replace(b'=', b'')
        data = self._prefix + data + self._suffix

        return self.ctr.encrypt(data)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.ctr.decrypt(ciphertext=ciphertext)
    

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
    
def findPrefixLength(oracle: Oracle):
    # Like challenge 16, make two slightly different ciphertexts and compare them until they are different
    c1 = oracle.encrypt(b'A')
    c2 = oracle.encrypt(b'B')

    prefixLength = 0
    while c1[prefixLength] == c2[prefixLength]:
        prefixLength += 1
    
    return prefixLength

def CTRBitFlip(oracle: Oracle, prefixLength: int) -> bytes:
    # The key insight here is to recognize that we're dealing with XOR and can build the ciphertext
    # with our injected text using its properties
    # The part we can keep will be XORed with zeroes. The part we want to modify will be built with
    # padded fake input, which, when XORed again will give the original part of the ciphertext in tact,
    # and between these padded parts, we put the injected text to make ourselves admin
    injectedText = b";admin=true"
    part1 = b'A' * len(injectedText)
    # This produces: injectedText ^ As
    part2 = cryptopals.xorAll((injectedText, part1))

    # Encrypting this will produce: prefix + (part2 ^ keystream) + suffix
    ciphertext = oracle.encrypt(part1)

    # Building the ciphertext mask with 0s + part2 + 0s
    modded = bytes([0] * prefixLength) + part2
    modded = modded + bytes([0] * (len(ciphertext) - len(modded)))
    # XORing ciphertext with modded: (prefix + (part2 ^ keystream) + suffix) ^ (0s + part2 + 0s)
    #                            =>  (prefix + (injectedText ^ keystream) + suffix)
    targetCiphertext = cryptopals.xorAll((ciphertext, modded))

    return targetCiphertext




def main():
    oracle = Oracle()
    prefixLength = findPrefixLength(oracle)
    # Confirm cound prefix length
    assert len(oracle._prefix) == prefixLength

    adminCiphertext = CTRBitFlip(oracle, prefixLength)
    print(oracle.decrypt(adminCiphertext))


if __name__ == "__main__":
    main()