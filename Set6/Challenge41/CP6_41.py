from Crypto.Util.number import getPrime
from hashlib import sha256
from random import randint, SystemRandom

#######################################################################
# Setup
class Role(object):
    def __init__(self):
        pass

def cryptrand(N, n = 1024):
    return SystemRandom().getrandbits(n) % N

def egcd(a, m):
    if a == 0: return (m, 0, 1)
    else:
        g, x, y = egcd(m % a, a)
        return g, y - (m // a) * x, x

def invmod(a, m):
    g, x, y = egcd(a, m)
    if g == 1: return x % m

#######################################################################
# RSA class and functions
class RSA(object):
    def _egcd(self, a, m):
        if a == 0: return (m, 0, 1)
        else:
            g, x, y = self._egcd(m % a, a)
            return g, y - (m // a) * x, x

    def _invmod(self, a, m):
        g, x, y = self._egcd(a, m)
        if g == 1: return x % m

    def _mk_keys(self):
        e = 3; et = 3
        while et % e == 0:
            p = getPrime(512); q = getPrime(512)
            n = p * q; et = (p - 1) * (q - 1)
            print "..."
        d = self._invmod(e, et)
        self.pub = [e, n]; self.prv = [d, n]

    def __init__(self):
        self._mk_keys()

    def encrypt(self, pt):
        m = int(pt.encode("hex"), 16)
        ct = pow(m, self.pub[0], self.pub[1])
        return ct

    def decrypt(self, ct):
        m = pow(ct, self.prv[0], self.prv[1])
        pt = "%x" % m
        if len(pt) % 2: pt = "0" + pt
        return pt.decode("hex")

#######################################################################
# Server response
def req_dc(ct):
    pt = RSA1.decrypt(ct)
    pthash = sha256(pt).hexdigest(); print "\nhash:", pthash

    if pthash in S.hashes: print "\n!!!:  Submission Error"
    S.hashes.append(pthash)

    print "\npt:  ", pt; return pt

#######################################################################
# Server response
def recover_pt(ct):
    N = RSA1.pub[1]; E = RSA1.pub[0]; S = 0
    while S <= 1: S = cryptrand(N)

    Ct = (pow(S, E, N) * ct) % N

    Pt = req_dc(Ct)
    I = int(Pt.encode("hex"), 16)

    mh = "%x" % ((I * invmod(S, N)) % N)

    if len(mh) % 2: mh = "0" + mh
    pt = mh.decode("hex")
    print "\nmap: ", pt; return pt

#######################################################################
# Main routine (also opens subprocess)
if __name__ == "__main__":
    S = Role(); S.hashes = []
    RSA1 = RSA()

    message = {"time": "1356304276",
               "social": "555-55-5555"}
    pt = ""
    for x in message:
        pt += x + "=" + message[x] + "&"
    pt = pt[: -1]; print "\npt:  ", pt
    ct = RSA1.encrypt(pt); print "\nct:  ", ct

    print "\n\nRequest 1:"
    pt = req_dc(ct)
    print "\n\nRequest 2:"
    req_dc(ct)

    print "\n\nAttack:"
    pt = recover_pt(ct)
    print "\n"
