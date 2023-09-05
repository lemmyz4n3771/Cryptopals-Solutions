from Crypto.Cipher import AES
from os import urandom

class ECBOracle:
    def __init__(self):
        self._key = urandom(AES.key_size[0])
    def encrypt(self, email):
        encoded = encodeJson(profile_for(email))
        asBytes = encoded.encode()
        return aesECBEncrypt(asBytes, self._key)
    def decrypt(self, ciphertext):
        return aesECBDecrypt(ciphertext, self._key)

def profile_for(email: str):
    email = email.replace('&', '').replace('=','')
    json = {}
    json["email"] = email
    json["uid"] = 10
    json["role"] = "user"
    return json

def encodeJson(json: dict):
    encoded = ""
    for e in json.items():
        encoded += e[0] + '=' + str(json[e[0]]) + '&'
    return encoded[:-1]

def aesECBDecrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7Unpad(cipher.decrypt(data))

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