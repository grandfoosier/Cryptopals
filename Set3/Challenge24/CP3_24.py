from random import randint
from time import time
import array
import base64

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
            self.mt[i] = _int32(1812433253 *
                (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

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

def rngks_encrypt(pt, seed):
    ct = ""
    n = len(pt) / 4
    m = len(pt) - (4 * n)
    rngks = MT19937(seed)

    for i in range (0, n):
        x = rngks.extract_number()
        hexx = hex(x)[2:].zfill(8)

        for j in range (0, 4):
            b8_p = ord(pt[(4 * i) + j])
            b8_r = int(str(hexx)[2 * j: (2 * j) + 2], 16)
            ct = ct + chr(b8_p ^ b8_r)

    x = rngks.extract_number()
    hexx = hex(x)[2:].zfill(8)

    for j in range (0, m):
        b8_p = ord(pt[(4 * n) + j])
        b8_r = int(str(hexx)[2 * j: (2 * j) + 2], 16)
        ct = ct + chr(b8_p ^ b8_r)

    return ct

def generate_plaintext():
    n = randint(7, 21)
    pt = ""

    for i in range (0, n):
        c = randint(32, 126)
        pt = pt + chr(c)

    pt = pt + "AAAAAAAAAAAAAAA"
    return pt

def make_cipher():
    seed = randint(0, 65536)
    pt = generate_plaintext()
    print ""
    print pt
    ct = rngks_encrypt(pt, seed)
    return [ct, seed]

def formulate_problem(ct):
    ks = [0] * (len(ct) / 4)
    minus = -12 - (len(ct) % 4)

    for i in range (0, 3):
        b8 = ""

        for j in range (0, 4):
            c = ord(ct[minus + (4 * i) + j]) ^ ord("A")
            hexc = hex(c)[2:].zfill(2)
            b8 = b8 + str(hexc)

        ks[-3 + i] = int(b8, 16)

    return ks

def check_seeds(ks):
    for i in range (0, 65536):
        print "\r %i" % i,
        rng = MT19937(i)
        outputs = []

        for j in range (0, len(ks)):
            outputs.append(rng.extract_number())

        if outputs[-3:] == ks[-3:]:
            return i

    print "fail"

def generate_reset_token():
    text = chr(0) * 30
    # text = "Hey you can use your account again now!"
    # print ""
    # text = raw_input("> ")
    print ""

    ct = ""
    n = len(text) / 4
    m = len(text) - (4 * n)

    which = randint(0, 1)

    if which == 0: seed = int(time()); print seed
    else: seed = randint(0, 4000000000); print "not time"

    rnd = MT19937(seed)

    for i in range (0, n):
        x = rnd.extract_number()
        hexx = hex(x)[2:].zfill(8)

        for j in range (0, 4):
            b8_p = ord(text[(4 * i) + j])
            b8_r = int(str(hexx)[2 * j: (2 * j) + 2], 16)
            ct = ct + chr(b8_p ^ b8_r)

    x = rnd.extract_number()
    hexx = hex(x)[2:].zfill(8)

    for j in range (0, m):
        b8_p = ord(text[(4 * n) + j])
        b8_r = int(str(hexx)[2 * j: (2 * j) + 2], 16)
        ct = ct + chr(b8_p ^ b8_r)

    token = base64.b64encode(ct)
    print token + "\n"
    return token

def freqtest(text):
    score = 0
    arr = array.array('B', text)

    for i in range (len(arr)):
        if   arr[i] in [69,101]:    score += 3.125 # E
        elif arr[i] in [84,116]:    score += 2.366 # T
        elif arr[i] in [65,97]:     score += 2.112 # A
        elif arr[i] in [79,111]:    score += 1.997 # O
        elif arr[i] in [73,105]:    score += 1.899 # I
        elif arr[i] in [78,110]:    score += 1.806 # N
        elif arr[i] in [83,115]:    score += 1.633 # S
        elif arr[i] in [82,114]:    score += 1.566 # R
        elif arr[i] in [72,104]:    score += 1.540 # H
        elif arr[i] in [68,100]:    score += 1.123 # D
        elif arr[i] in [76,108]:    score += 1.034 # L
        elif arr[i] in [85,117]:    score += 0.748 # U
        elif arr[i] in [67,99]:     score += 0.705 # C
        elif arr[i] in [77,109]:    score += 0.679 # M
        elif arr[i] in [70,102]:    score += 0.599 # F
        elif arr[i] in [89,121]:    score += 0.550 # Y
        elif arr[i] in [87,119]:    score += 0.545 # W
        elif arr[i] in [71,103]:    score += 0.527 # G
        elif arr[i] in [80,112]:    score += 0.473 # P
        elif arr[i] in [66,98]:     score += 0.387 # B
        elif arr[i] in [86,118]:    score += 0.288 # V
        elif arr[i] in [75,107]:    score += 0.179 # K
        elif arr[i] in [88,120]:    score += 0.045 # X
        elif arr[i] in [81,113]:    score += 0.029 # Q
        elif arr[i] in [74,106]:    score += 0.027 # J
        elif arr[i] in [90,122]:    score += 0.018 # Z
        elif arr[i] in [32]:        score += 1     # Space
        elif arr[i] in [48,49,50,51,52,53,54,55,56,57]:
            score += 0                             # 0-9
        elif arr[i] not in [0,33,34,39,44,45,46,47,58,59,63]:
            score = -1; break

    return score

def check_token(token, seed):
    rnd = MT19937(seed)
    token = base64.b64decode(token)
    ct = ""
    n = len(token) / 4
    m = len(token) - (4 * n)

    for i in range (0, n):
        x = rnd.extract_number()
        hexx = hex(x)[2:].zfill(8)

        for j in range (0, 4):
            b8_p = ord(token[(4 * i) + j])
            b8_r = int(str(hexx)[2 * j: (2 * j) + 2], 16)
            ct = ct + chr(b8_p ^ b8_r)

    x = rnd.extract_number()
    hexx = hex(x)[2:].zfill(8)

    for j in range (0, m):
        b8_p = ord(token[(4 * n) + j])
        b8_r = int(str(hexx)[2 * j: (2 * j) + 2], 16)
        ct = ct + chr(b8_p ^ b8_r)

    score = freqtest(ct)

    if (score * 1.0 / len(token)) >= 0.5:
        print score
        print ct
        return True
    elif score == 0:
        print score
        print ct
        return True
    else: return False

def check_token_for_time_basis(token):
    now = time()

    for i in range (-300, 300):
        check = check_token(token, int(now + i))
        if check == True: print int(now + i); return 1

    print "fail"

def crack_RNGKS():
    cipher = make_cipher()
    print ""
    print cipher[0]
    ks = formulate_problem(cipher[0])
    print ""
    print ks
    print ""
    seed = check_seeds(ks)
    print "\r", "", seed
    if seed == cipher[1]: print " Pass! -", hex(seed)[2:].zfill(4)
    print "\n\n"

def crack_token():
    token = generate_reset_token()
    check_token_for_time_basis(token)
    print "\n\n"

crack_RNGKS()

crack_token()
