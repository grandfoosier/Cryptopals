from hashlib import sha256
from random import randint, SystemRandom
import array

#######################################################################
# Setup
def gen_key():
    key = array.array('B', [])

    for i in range (0, 16): key.append(randint(0,255))

    return key

def gen_psw():
    psw = ""; l = randint(8, 16)

    for i in range (0, l): psw = psw + chr(randint(97, 122))

    return psw

def cryptrand(N, n = 1024):
    return SystemRandom().getrandbits(n) % N

class Bignum(object):
    def __init__(self):
        self.big = (
            '00c037c37588b4329887e61c2da3324b1ba4b81a' +
            '63f9748fed2d8a410c2fc21b1232f0d3bfa02427' +
            '6cfd88448197aae486a63bfca7b8bf7754dfb327' +
            'c7201f6fd17fd7fd74158bd31ce772c9f5f8ab58' +
            '4548a99a759b5a2c0532162b7b6218e8f142bce2' +
            'c30d7784689a483e095e701618437913a8c39c3d' +
            'd0d4ca3c500b885fe3')
        self.big = int(self.big, 16)
        self.psw = gen_psw()

class Role(object):
    def __init__(self):
        pass

#######################################################################
# HMAC code
def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)

    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]

    return a3.tostring()

def hmac(fn, key, message):
    bsize = fn().block_size
    if len(key) > bsize:
        key = fn(key).digest()
    else:
        key += (b'\x00' * (bsize - len(key)))

    opad = strxor(b'\x5c' * bsize, key)
    ipad = strxor(b'\x36' * bsize, key)

    return fn(opad + fn(ipad + message).digest()).digest()

#######################################################################
# Client's functions
def c1():
    C.N = X.big; C.g = 2; C.k = 3
    C.I = b'foo@bar.gov'; C.psw = X.psw

    C.a = cryptrand(C.N)
    C.A = pow(C.g, C.a, C.N)
    return C.I, C.A

def c2(s, B):
    C.s = s; C.B = B
    x = int(sha256(str(C.s) + C.psw).hexdigest(), 16)

    u = int(sha256(str(C.A) + str(C.B)).hexdigest(), 16)

    Sc = pow(C.B - C.k * pow(C.g, x, C.N), C.a + u * x, C.N)

    K = sha256(str(Sc)).digest()

    C.HK = hmac(sha256, str(C.s), K)
    return C.HK

#######################################################################
# Server's functions
def s1(I, A):
    S.N = X.big; S.g = 2; S.k = 3
    S.I = I; S.psw = X.psw  # Password would be looked up

    S.s = cryptrand(S.N, 64)
    x = int(sha256(str(S.s) + S.psw).hexdigest(), 16)
    S.v = pow(S.g, x, S.N)

    S.A = A
    S.b = cryptrand(S.N)
    S.B = S.k * S.v + pow(S.g, S.b, S.N)
    return S.s, S.B

def s2(HK):
    u = int(sha256(str(S.A) + str(S.B)).hexdigest(), 16)

    Ss = pow(S.A * pow(S.v, u, S.N), S.b, S.N)

    K = sha256(str(Ss)).digest()

    S.HK = hmac(sha256, str(C.s), K)

    if S.HK == HK: return "OK"
    else: return "FAIL"

#######################################################################
# normal and hacked
def norm_proc():
    print "NORMAL:\n"
    print "Client and Server agree on N, g, k, I, and P\n"
    print "Server generates salt integer, hash verifier\n"
    print "Client sends I, A"
    I, A = c1()
    print I, A
    print "\nServer sends salt, B"
    s, B = s1(I, A)
    print s, B
    print "\nClient and Server calculate u, S, and K"
    print "\nClient sends HMACSHA256(K)"
    HK = c2(s, B)
    print HK
    print "\nServer sends back OK or not:"
    val = s2(HK)
    print val
    print ""

#######################################################################
# Main routine
if __name__ == "__main__":
    X = Bignum()
    C = Role(); S = Role()
    print ""
    norm_proc()
    print ""
