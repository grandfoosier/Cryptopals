from Crypto.Util.number import getPrime
from random import choice

#######################################################################
# Setup
def cryptrand(N, n = 1024):
    return SystemRandom().getrandbits(n) % N

def egcd(a, m): # Returns g, x, y where g = a*x + m*y = gcd(x, y)
    if a == 0: return (m, 0, 1)
    else: g, x, y = egcd(m % a, a); return g, y - (m // a) * x, x

def invmod(a, m):
    g, x, y = egcd(a, m)
    if g == 1: return x % m

class SmallPrimes(object):
    def __init__(self):
        self.pr = [
              2,   3,   5,   7,  11,  13,  17,  19,  23,  29,
             31,  37,  41,  43,  47,  53,  59,  61,  67,  71,
             73,  79,  83,  89,  97, 101, 103, 107, 109, 113,
            127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
            179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
            233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
            283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
            353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
            419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
            467, 479, 487, 491, 499, 503, 509, 521, 523, 541]

class Role(object):
    def __init__(self):
        pass

#######################################################################
# Encrypt and Decrypt
def mk_keys():
    e = 3; et = 3
    while et % e == 0:
        # p = choice(Sm.pr); q = choice(Sm.pr)
        p = getPrime(256); q = getPrime(256)
        print "p, q:", p, q
        n = p * q; et = (p - 1) * (q - 1)
    print "\nn:", n, "\n"
    d = invmod(e, et)
    C.pub = [e, n]; C.prv = [d, n]

def RSAencrypt(text):
    m = int(text.encode("hex"), 16)
    print "m:", m
    c = pow(m, C.pub[0], C.pub[1])
    return c

def RSAdecrypt(c):
    m = pow(c, C.prv[0], C.prv[1])
    print "m:", m
    text = "%x" % m
    if len(text) % 2: text = "0" + text
    return text.decode("hex")

#######################################################################
# Main routine (also opens subprocess)
if __name__ == "__main__":
    Sm = SmallPrimes()
    C = Role()

    mk_keys()
    c = RSAencrypt("Hello World!")
    print "c:", c
    m = RSAdecrypt(c)
    print m

    print ""
