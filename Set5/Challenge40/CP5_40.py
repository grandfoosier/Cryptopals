from Crypto.Util.number import getPrime
from random import choice
from sympy import integer_nthroot

#######################################################################
# Setup
def egcd(a, m): # Returns g, x, y where g = a*x + m*y = gcd(x, y)
    if a == 0: return (m, 0, 1)
    else: g, x, y = egcd(m % a, a); return g, y - (m // a) * x, x

def invmod(a, m):
    g, x, y = egcd(a, m)
    if g == 1: return x % m

class Role(object):
    def __init__(self):
        pass

#######################################################################
# Encrypt and Decrypt
def mk_keys():
    e = 3; et = 3
    while et % e == 0:
        p = getPrime(512); q = getPrime(512)
        n = p * q; et = (p - 1) * (q - 1)
        print "..."
    d = invmod(e, et)
    C.pub = [e, n]; C.prv = [d, n]

def RSAencrypt(text):
    m = int(text.encode("hex"), 16)
    c = pow(m, C.pub[0], C.pub[1])
    return c

def RSAdecrypt(c):
    m = pow(c, C.prv[0], C.prv[1])
    text = "%x" % m
    if len(text) % 2: text = "0" + text
    return text.decode("hex")

#######################################################################
# Attack routine
def CRT3(a, b, c, x, y, z):
    n = ((a * y * z * invmod(y * z, x)) +
         (b * x * z * invmod(x * z, y)) +
         (c * x * y * invmod(x * y, z))) % (x * y * z)
    return n

def e3RSAattack():
    text = (
        "The pellet with the poison's in the flagon with the dragon;" +
        " the vessel with the pestle has the brew that is true")
    mk_keys(); r0 = RSAencrypt(text); n0 = C.pub[1]
    mk_keys(); r1 = RSAencrypt(text); n1 = C.pub[1]
    mk_keys(); r2 = RSAencrypt(text); n2 = C.pub[1]

    n = CRT3(r0, r1, r2, n0, n1, n2)
    m, V = integer_nthroot(n, 3)
    text = "%x" % m
    if len(text) % 2: text = "0" + text

    return text.decode("hex")

#######################################################################
# Main routine (also opens subprocess)
if __name__ == "__main__":
    # Sm = SmallPrimes()
    C = Role()

    # print CRT(2, 3, 2, 3, 5, 7)
    msg = e3RSAattack()
    print msg

    print "\n"
