from Crypto.Util.number import getPrime, isPrime
from hashlib import sha1, sha256
from random import SystemRandom

#######################################################################
# DSA with saftey measures turned off (r, s can = 0)
class DSA_unsafe(object):
    def _cryptrand(self, N, n = 1024):
        return SystemRandom().getrandbits(n) % N

    def _egcd(self, a, m):
        if a == 0: return (m, 0, 1)
        else:
            g, x, y = self._egcd(m % a, a)
            return g, y - (m // a) * x, x

    def _invmod(self, a, m):
        g, x, y = self._egcd(a, m)
        if g == 1: return x % m

    def _mk_params(self):
        # print "\ngenerating %i bit prime q..." % self.N
        self.q = getPrime(self.N)
        # print "\n", self.q, "\n"

        # print "\ngenerating %i bit prime p..." % self.L
        while True:
            self.p = self._cryptrand(2 ** self.L, self.L)
            r = self.p % self.q; self.p += 1 - r
            while isPrime(self.p) != True:
                self.p = (self.p + self.q) % self.L
            if (self.p - 1) % self.q == 0: break
        # print "\n", self.p, "\n"

        h = self._cryptrand(self.p - 2, self.L) + 1
        # print "\ngenerating g..."
        self.g = pow(h, ((self.p - 1) / self.q), self.p)
        while self.g == 1:
            h = self._cryptrand(self.p - 2, self.L) + 1
            self.g = pow(h, ((self.p - 1) / self.q), self.p)
        # print "\n", self.g, "\n"

    def _chk_params(self):
        print "\nq is prime:", isPrime(self.q) == 1
        print "p is prime:", isPrime(self.p) == 1
        print "(p - 1) % q == 0:", (self.p - 1) % self.q == 0
        print "g != 1:", self.g != 1
        print "\n"

    def _mk_keys(self):
        self.prv = self._cryptrand(self.q - 1, self.L) + 1
        self.pub = pow(self.g, self.prv, self.p)

    def __init__(self, L = 2048, N = 256):
        self.L = L; self.N = N
        self._mk_params()
        # self._chk_params()
        self._mk_keys()

    def sign(self, msg):
        r = 0; s = 0
        H = long(sha256(msg).hexdigest(), 16)
        # while (r == 0 or s == 0):
        k = self._cryptrand(self.q - 1, self.N) + 1
        r = pow(self.g, k, self.p) % self.q
        I = H + (self.prv * r)
        s = ((I % self.q) * self._invmod(k, self.q)) % self.q

        # x = (((s * k - H) % self.q) *
        #      self._invmod(r, self.q)) % self.q
        # assert x == self.prv

        print (r, s); return (r, s)

    def verify(self, msg, (r, s)):
        # if ((r <= 0) or (r >= self.q)):
        #     print "r out of range"
        #     return False
        # if ((s <= 0) or (s >= self.q)):
        #     print "s out of range"
        #     return False
        w = self._invmod(s, self.q) % self.q
        H = long(sha256(msg).hexdigest(), 16)
        u1 = (H * w) % self.q
        u2 = (r * w) % self.q
        v = (((pow(self.g, u1, self.p)) *
              (pow(self.pub, u2, self.p))) % self.p) % self.q
        return v == r

#######################################################################
# Find private key
def tamper():
    DSA1.p = long(
        "800000000000000089e1855218a0e7dac38136ffafa72eda7" +
        "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6" +
        "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe" +
        "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2" +
        "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87" +
        "1a584471bb1", 16)
    DSA1.q = long(
        "f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
    DSA1.g = long(
        "00", 16)
    DSA1._mk_keys()
    print "g = 0.  pub:", DSA1.pub, "\n"

    (r, s) = DSA1.sign("hi mom")
    val = DSA1.verify("hi mom", (r, s))
    print "'hi mom' Verified =", val
    val = DSA1.verify("bye mom", (r, s))
    print "'bye mom' Verified =", val, "\n\n"

    print "g = p + 1\n"
    DSA1.g = DSA1.p + 1
    DSA1._mk_keys()

    z = long(sha256("Hello, world").hexdigest(), 16)
    r = pow(DSA1.pub, z, DSA1.p) % DSA1.q
    s = (r * DSA1._invmod(z, DSA1.q)) % DSA1.q
    val = DSA1.verify("Hello, world", (r, s))
    print "'Hello, world' Verified =", val

    z = long(sha256("Goodbye, world").hexdigest(), 16)
    r = pow(DSA1.pub, z, DSA1.p) % DSA1.q
    s = (r * DSA1._invmod(z, DSA1.q)) % DSA1.q
    val = DSA1.verify("Goodbye, world", (r, s))
    print "'Goodbye, world' Verified =", val

#######################################################################
# Main routine
if __name__ == "__main__":
    print "\nInitiating DSA..."
    DSA1 = DSA_unsafe(1024, 160)
    # DSA1 = DSA()

    print "\n\nTampering with params...\n"
    tamper()

    print "\n"
