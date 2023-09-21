import cryptopals
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

class Oracle():
    def __init__(self):
        self.key = get_random_bytes(AES.block_size)
        self.nonce = self.key
        self._prefix = b"comment1=cooking%20MCs;userdata="
        self._suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    
    def encrypt(self, plaintext: bytes) -> bytes:
        data = plaintext.replace(b';', b'').replace(b'=', b'')
        data = self._prefix + data + self._suffix

        ciphertext = cryptopals.aesCBCEncrypt(data, self.key, iv=self.nonce, setPadding=True)
        return ciphertext

    def decryptCheckAdmin(self, ciphertext: bytes) -> bool:
        decrypted = cryptopals.aesCBCDecrypt(ciphertext, key=self.key, iv=self.nonce, unpad=True)

        # Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found. 
        try:
            decoded = decrypted.decode('ascii')
        except UnicodeDecodeError:
            raise ValueError('Unexpected ascii found', decrypted)

        return ';admin=true;' in decoded

def findKey(oracle: Oracle):
    # Use your code to encrypt a message that is at least 3 blocks long
    # AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
    ciphertext = oracle.encrypt(b'A' * AES.block_size * 3)
    ciphertext = bytearray(ciphertext)
    # Modify the message (you are now the attacker):
    # C_1, C_2, C_3 -> C_1, 0, C_1
    ciphertext[AES.block_size:(AES.block_size * 2)] = bytes([0] * AES.block_size)
    ciphertext[(AES.block_size * 2) : (AES.block_size * 3)] = ciphertext[:AES.block_size]
    # Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found. 

    try:
        oracle.decryptCheckAdmin(ciphertext)
        raise Exception('detect_key failed')
    except ValueError as e:
        decrypted = e.args[1]

    # As the attacker, recovering the plaintext from the error, extract the key:
    # P'_1 XOR P'_3
    key = cryptopals.xorAll((decrypted[:AES.block_size], decrypted[AES.block_size * 2 : AES.block_size * 3]))
    return key

def main():
    oracle = Oracle()
    key = findKey(oracle)

    assert key == oracle.key
    print("Cracked key")

if __name__ == "__main__":
    main()