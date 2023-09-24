from cryptopals import sha1, sha1MAC, leftRotate
import struct
from Crypto.Random import get_random_bytes

# To implement the attack, first write the function that computes the MD padding of an arbitrary 
# message and verify that you're generating the same padding that your SHA-1 implementation is using.
def mdPadding(messageLength: int) -> bytes:
    # Just copy the code for pre-processing sha1 padding
    # ensure multiple of 8
    ml = messageLength * 8

    # append the bit '1' to the message
    padding = bytes([0x80])

    # append bits '0' to match len of 448 (mod 512) bits
    padLength = (448 // 8) - ((messageLength+ len(padding)) % (512 // 8))
    padLength = (512 // 8) + padLength if padLength < 0 else padLength
    padding += bytes(padLength)

    # append ml, the original message length in bits, as a 64-bit big-endian integer.
    padding += ml.to_bytes(64 // 8, byteorder='big')

    # the total length is a multiple of 512 bits (64 bytes)
    assert ((messageLength + len(padding)) % 64 == 0)

    return padding

def lengthExtensionAttack(originalMessage: bytes, originalMac: bytes, newMessage: bytes, keyLength: int) -> tuple[bytes, bytes]:
    # take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a 
    # SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c)

    # Note that h0, h1, h2, h3, h4 are 4 bytes each and we're undoing this operation:
    # finalHash = (struct.pack(">I", i) for i in [h0, h1, h2, h3, h4])
    h0, h1, h2, h3, h4 = [struct.unpack(">I", originalMac[i:i + 4])[0] for i in range(0, 20, 4)]

    # The final message you actually forge will be:
    # SHA1(key || original-message || glue-padding || new-message)
    messageLength = keyLength + len(originalMessage)
    gluePadding = mdPadding(messageLength)
    finalMessage = originalMessage + gluePadding + newMessage

    newLength = len(finalMessage) + keyLength

    forgedMAC= sha1(newMessage, h0=h0, h1=h1, h2=h2, h3=h3, h4=h4, setLength=newLength)

    return finalMessage, forgedMAC

def main():
    key = get_random_bytes(16)
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    injectedText = b";admin=true"
    mac = sha1MAC(message, key)
    print(f"MAC: {mac}")

    finalMessage, forgedMac = lengthExtensionAttack(message, mac, injectedText, 16)
    print(f"Final message: {finalMessage}")
    print(f"Forged mac: {forgedMac}")

    mac2 = sha1MAC(finalMessage, key)
    print(f"mac2: {mac2}")
    assert forgedMac == mac2


if __name__ == "__main__":
    main()