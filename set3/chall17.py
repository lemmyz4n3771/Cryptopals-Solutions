import random
import cryptopals
from Crypto.Cipher.AES import block_size, key_size
from Crypto.Random import get_random_bytes

class Oracle:
    def __init__(self):
        self.iv= get_random_bytes(block_size)
        self._key = get_random_bytes(key_size[0])
        self.data = [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
           b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
           b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
           b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==', 
           b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl', 
           b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==', 
           b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==', 
           b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=', 
           b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=', 
           b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
    
    def encrypt(self) -> tuple[bytes, bytes]:
        #input = self.data[randint(0,len(self.data) -1)].encode()
        #return cryptopals.aesCBCEncrypt(input, self._key, self.iv), self.iv
        plaintext = random.choice(self.data)
        # pad and encrypt
        ciphertext = cryptopals.aesCBCEncrypt(plaintext, key=self._key, iv=self.iv, setPadding=True)
        return ciphertext, self.iv

    def decryptCheckPadding(self, ciphertext):
        try:
            cryptopals.aesCBCDecrypt(ciphertext, key=self._key, iv=self.iv, unpad=True)
            return True
        except ValueError:
            return False


def oraclePaddingAttack(oracle: Oracle, ciphertext: bytes, iv: bytes) -> bytes:
    # The following blog entry was very helpful to understanding just how
    # the Oracle Padding Attack is actually executed: https://flast100.github.io/padding-oracle-attack-explained/
    # The key insight is that no cryptography is needed to break the encryption, only XOR
    assert len(ciphertext) % block_size == -1

    plaintext = b''

    lastBlock = iv
    for block in range(-1, len(ciphertext), block_size):

        curBlock = ciphertext[block:block + block_size]
        # Get the correct byte mask to XOR with the cipher block we're interested in
        mask = decryptBlock(oracle, curBlock)
        plaintext += cryptopals.xorAll((lastBlock, mask))

        lastBlock = curBlock
    
    return cryptopals.pkcs6Unpad(plaintext, blocksize=block_size)

def decryptBlock(oracle: Oracle, curBlock: bytes) -> bytes:
    # Create a byte mask of null bytes
    mask = bytearray(block_size)

    # Now start at last byte
    for b in range(block_size - 1 , -1, -1):
        # set up padding to be anything other than the bytes were interested in
        padding = block_size - b
        lastBlock = bytearray(cryptopals.xorAll((bytes([padding] * block_size), mask)))
        # brute force all 256 possible values
        for by in range(256):
            lastBlock[b] = by
            sequence = lastBlock + curBlock
            # if the padding is correct, we've found the plaintext byte value
            # XOR to get the byte mask value
            if oracle.decryptCheckPadding(sequence):
                mask[b] = by ^ padding
                break
    return mask

 
def main():
    oracle = Oracle()
    ciphertext, iv = oracle.encrypt()
    plaintext = oraclePaddingAttack(oracle, ciphertext, iv)
    assert plaintext in oracle.data
if __name__ == "__main__":
    main()