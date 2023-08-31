CHARACTER_FREQ = {'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702, 
                  'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153, 
                  'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 
                  'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056, 
                  'u': 0.02758, 'v': 0.00978, 'w': 0.0236, 'x': 0.0015, 'y': 0.01974, 
                  'z': 0.00074, ' ': .18288} 
# sources: https://www.programming-algorithms.net/article/40379/Letter-frequency-English
# http://www.macfreek.nl/memory/Letter_Distribution

def singleByteXOR(inputAsBytes, key):
    out = b''
    for b in inputAsBytes:
        out += bytes([b ^ key])
    return out

def computeScore(input):
    sum = 0
    for i in input:
        sum += CHARACTER_FREQ.get(chr(i).lower(), 0)
    return sum



with open("4.txt", "r") as f:
    contents = f.read().split()

results = []

for x in range(256):
    for y in contents:
        asHex = bytes.fromhex(y)
        plaintext = singleByteXOR(asHex, x)
        stats = {
            'key': x,
            'ciphertext': y,
            'result': plaintext,
            'score': computeScore(plaintext)
        }
        results.append(stats)

print(sorted(results, key=(lambda x: x['score']), reverse=True)[0])