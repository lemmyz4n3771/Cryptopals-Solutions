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
    padLength = data[-1]
    return data[:-padLength]


data = b"YELLOW SUBMARINE"

print(pkcs7Pad(data, 20))

data = b"LEMMY"
padded = pkcs7Pad(data, 20)
print(padded)
print(isPKCS7Padded(padded))
print(isPKCS7Padded(padded[-2:]))
print(pkcs7Unpad(padded))
