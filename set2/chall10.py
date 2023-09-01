from Crypto.Cipher import AES
from base64 import b64decode

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

def aesECBDecrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7Unpad(cipher.decrypt(data))

def aesECBEncrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7Pad(data, AES.block_size))

def xor(data1, data2):
    return bytes([b1 ^ b2 for b1, b2 in zip(data1, data2)])


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

def aesCBCDecrypt(data, key, iv):
    plaintext = b''
    prev = iv

    for b in range(0, len(data), AES.block_size):
        block = data[b:b + AES.block_size]
        decrypted = aesECBDecrypt(block, key)
        xored = xor(prev, decrypted)
        plaintext += xored
        prev = block
    
    return pkcs7Unpad(plaintext)

KEY = b'YELLOW SUBMARINE'
iv = AES.block_size * b'\x00'
with open("10.txt", 'r') as f:
    contents = b64decode(f.read())

print(aesCBCDecrypt(contents, KEY, iv))

test = b'Lemmy was here'
encrypted = aesCBCEncrypt(test, KEY, iv)
print(encrypted)
print(aesCBCDecrypt(encrypted, KEY, iv))