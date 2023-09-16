from time import time, sleep
from random import randint
from chall21 import MT19937


def genRand() -> tuple:
    sleep(randint(40, 1000))
    seed = round(time())

    rng = iter(MT19937(seed=seed))
    sleep(randint(10, 20))

    return next(rng), seed

def findSeed(targetVal: int) -> int:
    seed = round(time())
    guess = next(iter(MT19937(seed=seed)))
    while guess != targetVal:
        seed -= 1
        guess = next(iter(MT19937(seed=seed)))
    return seed

def main():
    rand, seed = genRand()
    guess = findSeed(rand)
    assert guess == seed
    print("Guessed right")

if __name__ == "__main__":
    main()