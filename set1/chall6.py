import base64
from itertools import combinations

CHARACTER_FREQ = {'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702, 
                  'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153, 
                  'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 
                  'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056, 
                  'u': 0.02758, 'v': 0.00978, 'w': 0.0236, 'x': 0.0015, 'y': 0.01974, 
                  'z': 0.00074, ' ': .18288} 
# sources: https://www.programming-algorithms.net/article/40379/Letter-frequency-English
# http://www.macfreek.nl/memory/Letter_Distribution

def hamming(dataA, dataB):
    assert len(dataA) == len(dataB)
    return sum([bin(dataA[i] ^ dataB[i]).count('1') for i in range(len(dataA))])
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

def brute(input):
    results = []

    for x in range(256):
        plaintext = singleByteXOR(input, x)
        stats = {
            'key': x,
            'result': plaintext,
            'score': computeScore(plaintext)
        }
        results.append(stats)
    return sorted(results, key=(lambda x: x['score']), reverse=True)[0]

def repeatingKeyXOR(data, key):
    i = 0
    out = b''
    for d in data:
        out += bytes([d ^ key[i]])
        i = i + 1
        if i == len(key):
            i = 0
    return out

with open("6.txt", 'r') as f:
    contents = base64.b64decode(f.read())

normalizedDistance = {}

for keySize in range(2, 41):
    blocks = [contents[i: i + keySize] for i in range(0,len(contents), keySize)][:4]

    pairs = combinations(blocks, 2)

    distance = 0
    numPairs = 0
    for x, y in pairs:
        numPairs += 1
        distance += hamming(x, y)
    average = distance / numPairs
    normalized = average / keySize
    normalizedDistance[keySize] = normalized

possibleKeySizes = sorted(normalizedDistance, key=normalizedDistance.get)[:3]
#print(possibleKeySizes)

candidates = []

for p in possibleKeySizes:
    key = b''
    for i in range(p):
        block = b''

        for j in range(i, len(contents), p):
            block += bytes([contents[j]])
        key += bytes([brute(block)['key']])
    candidates.append((repeatingKeyXOR(contents, key), key)) 

print(max(candidates, key=lambda s: computeScore(s[0])))