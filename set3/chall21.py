class MT19937:
    # Pseudo code: https://en.wikipedia.org/wiki/Mersenne_Twister
    # coefficients for MT19937 are
    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF)
    (s,b) = (7, 0x9D2C5680)
    (t,c,) = (15, 0xEFC60000)
    l = 18
    f = 1812433253
    # const int lower_mask = (1 << r) - 1 // That is, the binary number of r 1's
    LOWER_MASK = (1 << r) - 1
    wMask = (1 << w ) -1
    # const int upper_mask = lowest w bits of (not lower_mask)
    UPPER_MASK = wMask & ~LOWER_MASK

    # // Alternatively, seed with constant value; 5489 is used in reference C code
    def __init__(self, seed: int = 5489):
        self.MT = self.seed_mt(seed)
        self.index = self.n

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
        
        y = self.MT[self.index]
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= (y >> self.l)

        self.index += 1
        return self.wMask & y

    def seed_mt(self, seed: int) -> list:
        MT = [seed]
        # for i from 1 to (n - 1) { // loop over each element
        for i in range(1, self.n):
            # MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
            MT.append(self.wMask & (self.f * (MT[i-1] ^ (MT[i-1] >> (self.w - 2))) + i))
        return MT
    
    def twist(self): 
        # for i from 0 to (n-1)
        for i in range(self.n):
            # int x := (MT[i] and upper_mask) | (MT[(i+1) mod n] and lower_mask)
            x = (self.MT[i] & self.UPPER_MASK) + (self.MT[(i + 1) % self.n] & self.LOWER_MASK)
            # int xA := x >> 1
            xA = x >> 1
            # if (x mod 2) != 0 { // lowest bit of x is 1
            if (x % 2) != 0:
                # xA := xA xor a
                xA = xA ^ self.a
            # MT[i] := MT[(i + m) mod n] xor xA
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0

def main():
    for i in range(50):
        print(MT19937(i).extract_number())
    
    

if __name__ == "__main__":
    main()

