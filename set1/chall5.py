phrase = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = 'ICE'

def repeatingKeyXOR(data, key):
    i = 0
    out = b''
    for d in data:
        out += bytes([d ^ key[i]])
        i = i + 1
        if i == len(key):
            i = 0
    return out

phraseAsBytes = bytes(phrase, 'latin1')
keyAsBytes = bytes(key, 'latin1')

binResult = repeatingKeyXOR(phraseAsBytes, keyAsBytes)
print(binResult.hex())