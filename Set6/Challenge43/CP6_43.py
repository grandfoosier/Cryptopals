from Crypto.Util.number import getPrime, isPrime
from hashlib import sha1, sha256
from random import SystemRandom

#######################################################################
# DSA class and functions
class DSA(object):
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
        print "\ngenerating %i bit prime q..." % self.N
        self.q = getPrime(self.N)
        print "\n", self.q, "\n"

        print "\ngenerating %i bit prime p..." % self.L
        while True:
            self.p = self._cryptrand(2 ** self.L, self.L)
            r = self.p % self.q; self.p += 1 - r
            while isPrime(self.p) != True:
                self.p = (self.p + self.q) % self.L
            if (self.p - 1) % self.q == 0: break
        print "\n", self.p, "\n"

        h = self._cryptrand(self.p - 2, self.L) + 1
        print "\ngenerating g..."
        self.g = pow(h, ((self.p - 1) / self.q), self.p)
        while self.g == 1:
            h = self._cryptrand(self.p - 2, self.L) + 1
            self.g = pow(h, ((self.p - 1) / self.q), self.p)
        print "\n", self.g, "\n"

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
        self._chk_params()
        self._mk_keys()

    def sign(self, msg):
        r = 0; s = 0
        H = long(sha256(msg).hexdigest(), 16)
        while (r == 0 or s == 0):
            k = self._cryptrand(self.q - 1, self.N) + 1
            r = pow(self.g, k, self.p) % self.q
            I = H + (self.prv * r)
            s = ((I % self.q) * self._invmod(k, self.q)) % self.q

        x = (((s * k - H) % self.q) *
             self._invmod(r, self.q)) % self.q
        assert x == self.prv

        print (r, s); return (r, s)

    def verify(self, msg, (r, s)):
        if ((r <= 0) or (r >= self.q)):
            print "r out of range"
            return False
        if ((s <= 0) or (s >= self.q)):
            print "s out of range"
            return False
        w = self._invmod(s, self.q) % self.q
        H = long(sha256(msg).hexdigest(), 16)
        u1 = (H * w) % self.q
        u2 = (r * w) % self.q
        v = (((pow(self.g, u1, self.p)) *
              (pow(self.pub, u2, self.p))) % self.p) % self.q
        return v == r

#######################################################################
# Find private key
def find_prv():
    p = long(
        "800000000000000089e1855218a0e7dac38136ffafa72eda7" +
        "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6" +
        "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe" +
        "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2" +
        "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87" +
        "1a584471bb1", 16)
    q = long(
        "f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
    g = long(
        "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119" +
        "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5" +
        "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047" +
        "0f5b64c36b625a097f1651fe775323556fe00b3608c887892" +
        "878480e99041be601a62166ca6894bdd41a7054ec89f756ba" +
        "9fc95302291", 16)
    y = long(
        "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4" +
        "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004" +
        "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed" +
        "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b" +
        "bb283e6633451e535c45513b2d33c99ea17", 16)
    H = long(
        "d2d0714f014a9784047eaeccf956520045c45265", 16)
    (r, s) = (
        548099063082341131477253921760299949438196259240,
        857042759984254168557880549501802188789837994940)
    fpt = (
        "0954edd5e0afe5542a4adf012611a91912a3ec16")

    for i in range (2 ** 16):
        ri = pow(g, i, p) % q; print ("\r%i" % i),
        if ri == r: break

    x = (((s * i - H) % q) *
         DSA1._invmod(r, q)) % q
    prv = sha1("%x" % x).hexdigest()
    print prv, prv == fpt, "\n\n"
    return x

#######################################################################
# Main routine
if __name__ == "__main__":
    print "\nChecking DSA programming..."
    # DSA1 = DSA(1024, 160)
    DSA1 = DSA()
    (r, s) = DSA1.sign("hi mom")
    val = DSA1.verify("hi mom", (r, s))
    print "Verified =", val, "\n\n"

    print "Finding k given p, q, g, H, r, s...\n"
    find_prv()

    # msg = ("For those that envy a MC " +
    #        "it can be hazardous to your health\n" +
    #        "So be friendly, a matter of life and death, " +
    #        "just like a etch-a-sketch\n")
    # print sha1(msg).hexdigest()
