import cryptopals
from os import urandom
from Crypto.Cipher import AES
from functools import reduce

class CBCOracle:
    def __init__ (self):
        self._key = urandom(AES.key_size[0])
        self._iv = urandom(AES.block_size)
        self._prefix = "comment1=cooking%20MCs;userdata="
        self._suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    
    def encrypt(self, data: str):
        # The function should quote out the ";" and "=" characters.
        data = data.replace(';', '').replace('=', '')
        contents = (self._prefix + data + self._suffix).encode()
        return cryptopals.aesCBCEncrypt(contents, self._key, self._iv)
    
    def decryptCheckAdmin(self, ciphertext):
        data = cryptopals.aesCBCDecrypt(ciphertext, self._key, self._iv)
        # print(data)
        return b";admin=true;" in data

def CBCBitFlip(oracle: CBCOracle):
    # confirm blocksize
    blocksize = findBlocksize(oracle)
    # get the prefix length we're interested in
    prefixLength = findPrefixLength(oracle, blocksize)

    # ensure prefix length is a factor of the blocksize
    # if it isn't, set the pad length to make it so
    if prefixLength % blocksize != 0:
        padLength = blocksize - (prefixLength % blocksize)
    else:
        padLength = 0

    # now our input should be aligned to a new block
    prevBlockLength = prefixLength + padLength

    # encrypt two blocks worth of As
    plaintext = 'B' * padLength + 'A' * 2 * blocksize
    ciphertext = oracle.encrypt(plaintext)

    # now set up the block that we want to make us admin
    adminBlock = b";admin=true"
    # make sure admin block will be properly padded to fill exactly one blocksize
    adminBlock = b'A' * (blocksize - len(adminBlock)) + adminBlock

    # take one blocksize from the block we're interested in
    c1 = ciphertext[prevBlockLength: prevBlockLength + blocksize]
    # now XOR the section we wanted with As, then XOR that with the block that makes us admin, leaving us the admin section
    p2 = b'A' * blocksize
    c1Mod = xorAll((c1, p2, adminBlock))

    # concat it all up
    # up to prefix
    result = ciphertext[:prevBlockLength]
    # up to the section modified to make us admin
    result += c1Mod
    # the rest
    result += ciphertext[prevBlockLength + blocksize:]

    return result

def findPrefixLength(oracle: CBCOracle, blocksize):
    # Find length of common blocks
    commonLength = 0
    # ciphertext1 is the base case
    ciphertext1 = oracle.encrypt('')
    # ciphertext2 is slightly modified
    ciphertext2 = oracle.encrypt('A')
    # now compare the two
    for i in range(0, len(ciphertext2), blocksize):
        if ciphertext1[i:i+blocksize] != ciphertext2[i:i+blocksize]:
            commonLength = i
            break
    
    # the next region to get will be less than an entire blocksize, but  greater than the common region found
    blockSlice = slice(commonLength, commonLength + blocksize)
    # from the base case, select the next region we're interested in
    prevBlock = ciphertext1[blockSlice]
    padLength = 0

    # increase the plaintext to encrypt to gradually increase the ciphertext
    # if the region is still the same, we've found the length of padding in final block
    for i in range(1, blocksize + 2):
        nextBlock = oracle.encrypt('A'*i)[blockSlice]
        if nextBlock == prevBlock:
            padLength = i -1
            break
        prevBlock = nextBlock
    
    # return the sum, minus the padding
    return commonLength + blocksize - padLength


def findBlocksize(oracle: CBCOracle):
    initial = oracle.encrypt('')
    data = 'A'
    modded = oracle.encrypt(data)

    while len(initial) == len(modded):
        data += 'A'
        modded = oracle.encrypt(data)
    return len(modded) - len(initial)

def xorAll(data: tuple[bytes, ...]):
    assert len(set(map(len, data))) == 1

    asInt = map(lambda x: int.from_bytes(x, "big"), data)
    xored = reduce(lambda x, y: x ^ y, asInt)
    return xored.to_bytes(len(data[0]), "big")


def main():
    oracle = CBCOracle()
    adminCipher = CBCBitFlip(oracle)
    print(oracle.decryptCheckAdmin(adminCipher))

if __name__ == "__main__":
    main()