import math
import cryptopals
from Crypto.Cipher import AES
from base64 import b64decode
from os import urandom

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

ciphertext = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
ciphertext = b64decode(ciphertext)
ctrObj = AesCtrMode(b'YELLOW SUBMARINE', nonce=bytes(8), byteorder="little")
plaintext = ctrObj.decrypt(ciphertext)
print(plaintext)