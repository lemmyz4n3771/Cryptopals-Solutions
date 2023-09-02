from Crypto.Cipher import AES


def findDupes(ciphers):
    blocks = [ciphers[i:i + AES.block_size] for i in range(0, len(ciphers), AES.block_size)]
    dupes = len(blocks) - len(set(blocks))
    return dupes

def mostDupesIndex(ciphers):
    dupeList = []
    for i in range(len(ciphers)):
        dupeList.append(findDupes(data[i]))
    mostDupes = max(dupeList)
    return mostDupes, dupeList.index(mostDupes)

data = [bytes.fromhex(line.strip()) for line in open("8.txt", 'r')]
i, j = mostDupesIndex(data)
print(f"Most dupes in cipher at index {j} with {i} dupes")