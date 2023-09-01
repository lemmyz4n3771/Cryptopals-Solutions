from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = b"YELLOW SUBMARINE"

with open("7.txt", 'r') as f:
    data = b64decode(f.read())


cipher = AES.new(KEY, AES.MODE_ECB)
print(unpad(cipher.decrypt(data), AES.block_size))
#print(cipher.decrypt(data))