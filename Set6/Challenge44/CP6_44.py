from Crypto.Util.number import getPrime, isPrime
from hashlib import sha1, sha256
from random import SystemRandom

#######################################################################
# Setup
class Info(object):
    def __init__(self):
        fname = "CP6_44.txt"
        Ls = [line.rstrip('\n') for line in open(fname)]
        self.msgs = []; self.ss = []; self.rs = []; self.ms = []
        for i in range (len(Ls) / 4):
            self.msgs.append(Ls[i * 4][4: ])
            self.ss.append(long(Ls[i * 4 + 1][2: ]))
            self.rs.append(long(Ls[i * 4 + 2][2: ]))
            self.ms.append(long(Ls[i * 4 + 3][2: ], 16))

        self.p = long(
            "800000000000000089e1855218a0e7dac38136ffafa72eda7" +
            "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6" +
            "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe" +
            "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2" +
            "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87" +
            "1a584471bb1", 16)
        self.q = long(
            "f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
        self.g = long(
            "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119" +
            "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5" +
            "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047" +
            "0f5b64c36b625a097f1651fe775323556fe00b3608c887892" +
            "878480e99041be601a62166ca6894bdd41a7054ec89f756ba" +
            "9fc95302291", 16)
        self.pub = long(
            "2d026f4bf30195ede3a088da85e398ef869611d0f68f07" +
            "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8" +
            "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519" +
            "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430" +
            "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3" +
            "2971c3de5084cce04a2e147821", 16)

        print "\nInfo Loaded\n"

def egcd(a, m):
    if a == 0: return (m, 0, 1)
    else:
        g, x, y = egcd(m % a, a)
        return g, y - (m // a) * x, x

def invmod(a, m):
    g, x, y = egcd(a, m)
    if g == 1: return x % m

#######################################################################
# Find accidentally repeated private key
def find_repk_prv():
    fpt = ("ca8f6f7c66fa362d40760d135b763eb8527d3d52")
    xs = []

    for i in range (len(X.ms) - 1):
        for j in range (i + 1, len(X.ms)):
            if X.rs[i] == X.rs[j]:
                k = (((X.ms[i] - X.ms[j]) % X.q) *
                     (invmod((X.ss[i] - X.ss[j]) % X.q, X.q))) % X.q
                print "k:", k; print ""

                x1 = (((X.ss[i] * k - X.ms[i]) % X.q) *
                      invmod(X.rs[i], X.q)) % X.q
                x2 = (((X.ss[j] * k - X.ms[j]) % X.q) *
                      invmod(X.rs[j], X.q)) % X.q
                assert x1 == x2
                xs.append(x1)

    for i in range (1, len(xs)): assert xs[0] == xs[i]

    prv = sha1("%x" % xs[0]).hexdigest()
    print "\nx:", xs[0]
    print prv, prv == fpt, "\n\n"
    return xs[0]

#######################################################################
# Main routine
if __name__ == "__main__":
    X = Info()

    print "Finding k with message pairs...\n"
    find_repk_prv()
