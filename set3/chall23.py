from chall21 import MT19937
from random import randint

# Grab constants from algorithm
(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s,b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18

def cloneMT19937(rng: iter):
    # MT determines the next value of the rng. Once its value is determined,
    # create a new MT19937 object and set it to this value to have effectively
    # cloned the rng
    curState = []
    for i in range(n):
        curState.append(untemper(next(rng)))

    clone = MT19937(0)
    clone.MT = curState
    return clone    
    

def temper(y: int) -> int:
    # From algorithm
    y ^= (y >> u) & d
    y ^= (y << s) & b
    y ^= (y << t) & c
    y ^= (y >> l)

def untemper(y: int) -> int:
    # Inversion of temper algo, starting from algo's last operation first
    y = undoRightShift(y, l)
    y = undoLeftShift(y, t, c)
    y = undoLeftShift(y, s, b)
    y = undoRightShift(y, u)
    return y

def undoRightShift(x: int, shiftDistance: int):
    # We can ignore the first shiftDistance bytes because the original right shift makes those bits zeroes
    # which is unchanged in XOR. XORing the bytes within shiftDistance returns them to the original values
    inverted = to32BinRep(x)
    for i in range(shiftDistance, 32):
        inverted[i] ^= inverted[i - shiftDistance]
    return toIntRep(inverted)

def undoLeftShift(x: int, shift: int, andVal: int ) -> int:
    # Moving backwards, retrace left-shift operations to undo
    mask = to32BinRep(andVal)
    inverted = to32BinRep(x)
    for i in range(32 - shift - 1, -1, -1):
        inverted[i] ^= (inverted[i + shift] & mask[i])
    
    return toIntRep(inverted)


def to32BinRep(num: int) -> list[int]:
    # Convert integer to 32-bit binary representation for easy bitwise operations
    return [int(x) for x in "{:032b}".format(num)]

def toIntRep(bits: list) -> int:
    # Turn the binary representation into an integer again
    asString = [str(x) for x in bits]
    return int(''.join(asString), 2)

def main():
    # Seed with random 32-bit integer
    seed = randint(0, 2**32-1)
    # Create random-number generator
    rng = iter(MT19937(seed))
    # Create clone
    clone = iter(cloneMT19937(rng))
    # Prove that clone works
    for _ in range(100):
        assert next(clone) == next(rng)
    print("Successfully cloned")    

if __name__ == "__main__":
    main()