from time import time, sleep
from random import randint
import sys

def _int32(x):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & x)

class MT19937:

    def __init__(self, seed):
        # Initialize the index to 0
        self.index = 624
        self.mt = [0] * 624
        self.mt[0] = seed  # Initialize the initial state to the seed
        for i in range(1, 624):
            self.mt[i] = _int32(
                1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def extract_number(self):
        if self.index >= 624:
            self.twist()

        y = self.mt[self.index]

        # Right shift by 11 bits
        y = y ^ y >> 11
        # Shift y left by 7 and take the bitwise and of 2636928640
        y = y ^ y << 7 & 2636928640
        # Shift y left by 15 and take the bitwise and of y and 4022730752
        y = y ^ y << 15 & 4022730752
        # Right shift by 18 bits
        y = y ^ y >> 18

        self.index = self.index + 1

        return _int32(y)

    def twist(self):
        for i in range(624):
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            y = _int32((self.mt[i] & 0x80000000) +
                       (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
        self.index = 0

def wait(secs):
    start = time()
    while time() < start + secs:
        print '{0}\r'.format("%d%%" % (
            (time() - start) * 100 / secs)),

def slowrand():
    howlong = randint(40, 1000)
    print howlong
    wait(howlong)
    seed = int(time())
    print "\b"*32+ str(seed) + "\n"
    rnd = MT19937(seed)
    howlong = randint(40, 1000)
    print howlong
    wait(howlong)
    return rnd.extract_number()

def check_rands(newrand, secs):
    seed = int(time())
    for i in range (0, secs):
        rnd = MT19937(seed-i)
        checkrand = rnd.extract_number()
        if checkrand == newrand: break
    return seed - i

print ""
newrand = slowrand()
print "\b"*32+ str(newrand) + "\n"

print check_rands(newrand, 2000)
print ""

