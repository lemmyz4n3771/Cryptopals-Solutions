from Crypto.Random import get_random_bytes
from binascii import hexlify, unhexlify
from cryptopals import leftRotate
from struct import pack, unpack

class Oracle:

    def __init__(self):
        self._key = get_random_bytes(16)

    def isMACSame(self, message: bytes, digest: str):
        return md4MAC(message, self._key).getHexMAC() == digest

    def getHexDigest(self, message: bytes):
        return md4MAC(message, self._key).getHexMAC()

def md4MAC(msg: bytes, key: bytes):
    return MD4(key + msg)

class MD4:
    def __init__(self, message: bytes, messageLength: int = None, A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476):
        # To conduct the attack, it's necessary to be able to alter the values of A,B,C,D
        self.A, self.B, self.C, self.D = A, B, C, D

        # Ensure messageLength is a multiple of 8
        if messageLength is None:
            messageLength = len(message) * 8

        # Process Message in 16-Word Blocks
        # First 64 bytes
        while len(message) > 64:
            self._process(message[:64])
            message = message[64:]

        # Append Padding Bits
        # The message is "padded" (extended) so that its length (in bits) is congruent to 448, modulo 512.
        # Append Length
        length = pack('<Q', messageLength)
        message += b'\x80'
        message += bytes((56 - len(message) % 64) % 64)
        message += length

    def _process(self, chunk: bytes):
        mask = 0xffffffff

        # auxiliary functions

        def F(X, Y, Z):
            # F(X,Y,Z) = XY v not(X) Z
            return (X & Y) | (~X & Z)
    
        def G(X, Y, Z):
            #  G(X,Y,Z) = XY v XZ v YZ
            return (X & Y) | (X & Z) | (Y & Z)
    
        def H(X, Y, Z):
            # H(X,Y,Z) = X xor Y xor Z
            return X ^ Y ^ Z
    
        # /* Round 1. */
        #    /* Let [abcd k s] denote the operation
        #         a = (a + F(b,c,d) + X[k]) <<< s. */
        def r1(a, b, c, d, x, s):
            return leftRotate((a + F(b, c, d) + x) & mask, s)
    
        # /* Round 2. */
        #    /* Let [abcd k s] denote the operation
        #    a = (a + G(b,c,d) + X[k] + 5A827999) <<< s. */
        def r2(a, b, c, d, x, s):
            return leftRotate((a + G(b, c, d) + x + 0x5A827999) & mask, s)
    
        # /* Round 3. */
        #    /* Let [abcd k s] denote the operation
        #    a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s. */
        def r3(a, b, c, d, x, s):
            return leftRotate((a + H(b, c, d) + x + 0x6ED9EBA1) & mask, s)
        
        X = list(unpack('<' + "I" * 16, chunk))
        # /* Save A as AA, B as BB, C as CC, and D as DD. */
        AA, BB, CC, DD = self.A, self.B, self.C, self.D
        
        # /* Do the following 16 operations. */
        # [ABCD  0  3]  [DABC  1  7]  [CDAB  2 11]  [BCDA  3 19]
        # [ABCD  4  3]  [DABC  5  7]  [CDAB  6 11]  [BCDA  7 19]
        # [ABCD  8  3]  [DABC  9  7]  [CDAB 10 11]  [BCDA 11 19]
        # [ABCD 12  3]  [DABC 13  7]  [CDAB 14 11]  [BCDA 15 19]
        for i in range(16):
            k = i
            if i % 4 == 0:
                AA = r1(AA, BB, CC, DD, X[k], 3)
            elif i % 4 == 1:
                DD = r1(DD, AA, BB, CC, X[k], 7)
            elif i % 4 == 2:
                CC = r1(CC, DD, AA, BB, X[k], 11)
            elif i % 4 == 3:
                BB = r1(BB, CC, DD, AA, X[k], 19)

        # /* Do the following 16 operations. */
        # [ABCD  0  3]  [DABC  4  5]  [CDAB  8  9]  [BCDA 12 13]
        # [ABCD  1  3]  [DABC  5  5]  [CDAB  9  9]  [BCDA 13 13]
        # [ABCD  2  3]  [DABC  6  5]  [CDAB 10  9]  [BCDA 14 13]
        # [ABCD  3  3]  [DABC  7  5]  [CDAB 11  9]  [BCDA 15 13]
        # X pos: 0 4 8 12 1 5 9 13 2 6 10 14 3 7 11 15        
        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                AA = r2(AA, BB, CC, DD, X[k], 3)
            elif i % 4 == 1:
                DD = r2(DD, AA, BB, CC, X[k], 5)
            elif i % 4 == 2:
                CC = r2(CC, DD, AA, BB, X[k], 9)
            elif i % 4 == 3:
                BB = r2(BB, CC, DD, AA, X[k], 13)

        # /* Do the following 16 operations. */
        # [ABCD  0  3]  [DABC  8  9]  [CDAB  4 11]  [BCDA 12 15]
        # [ABCD  2  3]  [DABC 10  9]  [CDAB  6 11]  [BCDA 14 15]
        # [ABCD  1  3]  [DABC  9  9]  [CDAB  5 11]  [BCDA 13 15]
        # [ABCD  3  3]  [DABC 11  9]  [CDAB  7 11]  [BCDA 15 15]
        pos = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = pos[i]
            if i % 4 == 0:
                AA = r3(AA, BB, CC, DD, X[k], 3)
            elif i % 4 == 1:
                DD = r3(DD, AA, BB, CC, X[k], 9)
            elif i % 4 == 2:
                CC = r3(CC, DD, AA, BB, X[k], 11)
            elif i % 4 == 3:
                BB = r3(BB, CC, DD, AA, X[k], 15)

        # /* Then perform the following additions. (That is, increment each
        #   of the four registers by the value it had before this block
        #   was started.) */
        self.A = (self.A + AA) & mask
        self.B = (self.B + BB) & mask
        self.C = (self.C + CC) & mask
        self.D = (self.D + DD) & mask

    def asMAC(self):
        return pack('<4I', self.A, self.B, self.C, self.D)

    def getHexMAC(self):
        return hexlify(self.asMAC()).decode()

def mdPad(message: bytes):
    # Pad same way in MD4
    ml = len(message) * 8
    message += b'\x80'
    message += bytes((56 - len(message) % 64) % 64)
    message += pack('<Q', ml)

    return message


def lengthExtensionAttack(message: bytes, orgMAC: str, oracle: Oracle):
    # As in SHA1, the final message you actually forge will be:
    # MD4(key || original-message || glue-padding || new-message)
    injectedText = b';admin=true'

    # Guess key length in multiple of 8
    for kl in range(64):

        # Generate forged message
        finalMessage = mdPad(b'A' * kl + message)[kl:] + injectedText
        # Unpack MD4 state
        h = unpack('<4I', unhexlify(orgMAC))

        forgedMAC = MD4(injectedText, (kl + len(finalMessage)) * 8, h[0], h[1], h[2], h[3]).getHexMAC()

        if oracle.isMACSame(finalMessage, forgedMAC):
            return finalMessage, forgedMAC

    raise Exception("Attack failed: choose different key length")


def main():

    oracle = Oracle()

    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    mac = oracle.getHexDigest(message)
    #print(mac)

    finalMessage, forgedMAC = lengthExtensionAttack(message, mac, oracle)
    print(f"finalMessage: {finalMessage}\nforgedMAC: {forgedMAC}")

    assert b';admin=true' in finalMessage
    assert oracle.isMACSame(finalMessage, forgedMAC)
    print("Works")


if __name__ == '__main__':
    main()