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

def temper(y):
    # Right shift by 11 bits
    y = y ^ y >> 11
    # Shift y left by 7 and take the bitwise and of 2636928640
    y = y ^ y << 7 & 2636928640
    # Shift y left by 15 and take the bitwise and of y and 4022730752
    y = y ^ y << 15 & 4022730752
    # Right shift by 18 bits
    y = y ^ y >> 18

    return y

def unshiftright(r, shift):
    n = 32 / shift

    for i in range (0, n):
        mask = ((2 ** shift) - 1) << (32 - (shift * (i + 1)))
        x = r & mask
        r = r ^ (x >> shift)

    return r

def unshiftleft(r, shift, magnum):
    n = 32 / shift

    for i in range (0, n):
        mask = ((2 ** shift) - 1) << (shift * i)
        x = r & mask
        x = magnum & (x << shift)
        r = r ^ x

    return r

def untemper(n):
    # Left shift by 18 bits
    n = unshiftright(n, 18)
    # Shift n right by 15 and take the bitwise and of n and 4022730752
    n = unshiftleft(n, 15, 4022730752)
    # Shift n right by 7 and take the bitwise and of n and 2636928640
    n = unshiftleft(n, 7, 2636928640)
    # Left shift by 11 bits
    n = unshiftright(n, 11)

    return n

def test_untemper():
    for i in range (0, 10000):
        x = randint(1,4000000000)
        y = x
        x = temper(x)
        x = untemper(x)
        if x == y: print "\rpass",
        else: print "fail: %i" % y; pause = raw_input("")
        print str(i/100) + "%",

    print "\rpass 100%"

def get_outputs():
    o = []
    seed = randint(1,4000000000)
    rnd = MT19937(seed)

    for i in range (0, 624):
        o.append(rnd.extract_number())

    return o

def untemper_state(o):
    state = []

    for i in range (0, 624):
        state.append(untemper(o[i]))

    return state

def clone_MT19937(state):
    seed = 0
    shell = MT19937(seed)

    shell.index = 0
    shell.mt = state
    o2 = []

    for i in range (0, 624):
        o2.append(shell.extract_number())

    return o2

def check_clone():
    o = get_outputs()

    state = untemper_state(o)

    o2 = clone_MT19937(state)

    if o2 == o: return "pass"
    else: return "fail"

def test_clone():
    for i in range (0, 1000):
        pvf = check_clone()

        if pvf == "pass": print "\rpass",
        else: print "fail"; pause = raw_input("")
        print str(i/10) + "%",

    print "\rpass 100%"

# test_untemper()
print check_clone()
# test_clone()
