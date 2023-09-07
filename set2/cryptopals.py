from Crypto.Cipher import AES



def aesECBDecrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7Unpad(cipher.decrypt(data))

def aesECBEncrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7Pad(data, AES.block_size))

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

def xor(data1, data2):
    return bytes([b1 ^ b2 for b1, b2 in zip(data1, data2)])

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