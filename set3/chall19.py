from base64 import b64decode
from os import urandom
from Crypto.Random import get_random_bytes
import math
from Crypto.Cipher import AES
import cryptopals

class AesCtrMode:
    def __init__(self, key: bytes, nonce: bytes, byteorder="little"):
        if byteorder not in ["big", "little"]:
            raise ValueError("byteorder must be set to big or little endian")
        
        if nonce is None:
            self.nonce = urandom(8)
        else:
            self.nonce = nonce
        
        self.key = key
        self.byteorder = byteorder
        self.cipher = AES.new(self.key, AES.MODE_ECB)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        # Encryption is XOR'd against the plaintext
        keyStream = self.makeKeyStream(len(plaintext))
        ciphertext = cryptopals.xorAll((plaintext,keyStream))
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Decryption is identical to encryption: Generate the same keystream, XOR, and recover the plaintext. 
        keyStream = self.makeKeyStream(len(ciphertext))
        plaintext = cryptopals.xorAll((ciphertext, keyStream))
        return plaintext

    # Create a keystream that works for either big or little endian
    def makeKeyStream(self, inputLength: int) -> bytes:
        # CTR mode encrypts a running counter, producing a 16 byte block of keystream
        keyStream = b''
        for counter in range(math.ceil(inputLength / AES.block_size)):
            # concat nonce and counter
            concatNonceCounter = self.nonce + counter.to_bytes(AES.block_size // 2, byteorder=self.byteorder)
            keyStream += self.cipher.encrypt(concatNonceCounter)
        keyStream = keyStream[:inputLength]
        return keyStream

def byteOrderedStreams(streams: list) -> list:
    # Find the longest stream
    maxLen = max(map(len, streams))
    # Initialize output streams
    output = [bytes() for _ in range(maxLen)]
    # For each stream
    for stream in streams:
        # Take the byte position pos of stream and make it equal the byte value i in pos
        # So output will contain a list of bytes, where the ith index consists of the ith byte in each stream
        for pos, i in enumerate(stream):
            output[pos] += bytes([i])
    return output


def findKeystream(streams: list) -> bytes:
    # The principle at work here is that each byte location of the ciphertext has been XORed against
    # a single byte. So the first byte of each ciphertext has been XORed by the same byte, the second
    # byte has been XORed by the same byte, and so on.
    # So let's treat detact each byte location in all of the streams, then use single char XOR bruteforce
    # to find that particular key byte, then collect them all together and this will be our keystream
    individualStreams = byteOrderedStreams(streams)
    keyStream = bytes(map(cryptopals.brute, individualStreams))

    return keyStream

def main():

    b64Data = ['SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==', 'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=', 
               'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==', 'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=', 
               'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk', 'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==', 
               'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=', 'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==', 
               'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=', 'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl', 
               'VG8gcGxlYXNlIGEgY29tcGFuaW9u' , 'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==', 
               'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=', 'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==', 
               'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=', 'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=', 
               'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==', 'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==', 
               'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==', 'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==', 
               'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==', 'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==', 
               'U2hlIHJvZGUgdG8gaGFycmllcnM/', 'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=', 
               'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=', 'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=', 
               'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=', 'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==', 
               'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==', 'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=', 
               'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==', 'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu', 
               'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=', 'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs', 
               'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=', 'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0', 
               'SW4gdGhlIGNhc3VhbCBjb21lZHk7', 'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=', 
               'VHJhbnNmb3JtZWQgdXR0ZXJseTo=', 'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=']

    texts = [b64decode(i) for i in b64Data]

    key = get_random_bytes(AES.block_size)
    nonce = bytes(8)
    aesCTR = AesCtrMode(key, nonce, byteorder="little")
    encryptedTexts = [aesCTR.encrypt(i) for i in texts]

    keystream = findKeystream(encryptedTexts)
    # With the keystream found, what's left is to XOR the appropriate length keystream (which equals the encrypted text length)
    # and we get the plaintext
    for text in encryptedTexts:
        exactKeyLength = keystream[:len(text)]
        decrypted = cryptopals.xorAll((text, exactKeyLength))
        print(decrypted)

if __name__ == "__main__":
    main()