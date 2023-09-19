import math
import cryptopals
from os import urandom
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode

class EditOracle:
    def __init__(self):
        self.key = get_random_bytes(AES.block_size)
        self.aesCTR = AesCtrMode(self.key, nonce=None)

    def getCTRCiphertext(self):
        # Note: the key is referenced through the ECB exercise, which is listed in challenge 7
        key = b"YELLOW SUBMARINE"
        with open("25.txt", 'r') as f:
            contents = b64decode(f.read())
        
        plaintext = cryptopals.aesECBDecrypt(contents, key)
        # Encrypt plaintext as CTR
        ciphertext = self.aesCTR.encrypt(plaintext)
        return ciphertext

    # write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with 
    # different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newText)".
    def edit(self, ciphertext: bytes, offset: int, newText: bytes):
        # Don't need to pass the key is unnecessary because CTR is all XOR
        # Generate keystream
        keystream = self.aesCTR.makeKeyStream(len(ciphertext))
        # We want to edit a certain part of the keystream, so just extract that subset
        subKeystream = keystream[offset : offset + len(newText)]
        # Encrypt the newText with the appropriate subset of keystream
        insertCiphertext = cryptopals.xorAll((subKeystream, newText))
        # Combinine original ciphertext sections and newText ciphertext
        combinedCiphertext = ciphertext[:offset] + insertCiphertext + ciphertext[offset + len(insertCiphertext):]

        return combinedCiphertext


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
    
def main():
    oracle = EditOracle() 
    ciphertext = oracle.getCTRCiphertext()
    # The reason the reslt below is the plaintext is because CTR works by XOR and the thing we're XORing is
    # the ciphertext iself at offset 0 (which is the beginning of the ciphertext)
    plaintext = oracle.edit(ciphertext, offset=0, newText=ciphertext)
    print(plaintext)


if __name__ == "__main__":
    main()