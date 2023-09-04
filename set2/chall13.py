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

def parseCookie(cookie: str):
    parameters = cookie.split('&')
    json = {}
    for p in parameters:
        items = p.split('=')
        if items[1].isdigit():
            json[items[0]] = int(items[1])
        else:
            json[items[0]] = items[1]
    return json

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

def createAdmin(oracle: ECBOracle):
    # email=foo@bar.com&uid=10&role=user
    emailPrefix = AES.block_size - len("email=")
    roleSuffix = AES.block_size - len("admin")
    # blocked email must be crafted to place "admin" in block 2
    blockedEmail = 'A' * emailPrefix + "admin" + (chr(roleSuffix) * roleSuffix)
    # print(blockedEmail)
    # print(encodeJson(profile_for(blockedEmail)))
    encrypted1 = oracle.encrypt(blockedEmail)
    # print(encrypted1)
    # pwnEmail must be framed this way so that the profile_for and encodeJson functions will pass the following:
    # email=lemmyz@an.com&uid=10&role=user\0xc\0xc\0xc\0xc\0xc\0xc\0xc\0xc\0xc\0xc\0xc\0xc
    # ^block1---------^block2---------^block3---------------------------------------------
    pwnEmail = "lemmyz@an.com"
    encrypted2 = oracle.encrypt(pwnEmail)
    # print(encrypted2)
    # the result we weant will combine the first 2 blocksizes of pwnEmail with the second block of blockedEmail
    result = encrypted2[:32] + encrypted1[16:32]
    return result

def main():
    cookie = "foo=bar&baz=qux&zap=zazzle&admin=1"
    print(profile_for(cookie))
    email = "foo@bar.com"
    encoded = encodeJson(profile_for(email))
    print(encoded.encode())
    oracle = ECBOracle()
    cipher = oracle.encrypt(email)
    print(cipher)
    print(len(cipher))
    print(oracle.decrypt(cipher))
    r = createAdmin(oracle)
    print(r)
    print(oracle.decrypt(r))
if __name__ == "__main__":
    main()