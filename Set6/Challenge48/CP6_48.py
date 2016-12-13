from Crypto.Util.number import getPrime

#######################################################################
# RSA class and functions (w padding oracle)
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
            p = getPrime(self.b / 2); q = getPrime(self.b / 2)
            n = p * q; et = (p - 1) * (q - 1)
            print "..."
        d = self._invmod(e, et)
        self.pub = [e, n]; self.prv = [d, n]

    def __init__(self, b):
        self.b = b
        self._mk_keys()
        print "Initialized"

    def pad(self, pt):                                   # H -> H
        n_h = "%x" % self.pub[1]; L_n = len(n_h)
        n_ff = (L_n - (4 + 2 + len(pt)) + (L_n % 2)) / 2
        padded = ("0002" + ("5f" * n_ff) + "00" + pt)
        return padded

    def encrypt(self, pt):                               # S -> H
        m = int(pt.encode("hex"), 16)
        cti = pow(m, self.pub[0], self.pub[1])
        ct = "%x" % cti
        if len(ct) % 2: ct = "0" + ct
        return ct

    def decrypt(self, ct):                               # H -> S
        m = pow(long(ct, 16), self.prv[0], self.prv[1])
        pt = "%x" % m
        if len(pt) % 2: pt = "0" + pt
        return pt.decode("hex")

    def oracle(self, c):                                 # I -> B
        m = pow(c, self.prv[0], self.prv[1])
        pt = "%x" % m
        if len(pt) % 2: pt = "0" + pt
        n_h = "%x" % RSA1.pub[1]; L_n = len(n_h)
        n_0 = (L_n - len(pt))
        dig = ("0" * n_0) + pt
        return dig[0: 4] == "0002"

#######################################################################
# Bleichenbacher's PKCS 1.5 Padding Oracle Exploit
def divC(A, B):
    return A/B + ((A % B) > 0)

def divF(A, B):
    return A/B

def check(a, c):
    a = "%x" % a
    if len(a) % 2: a = "0" + a
    n_h = "%x" % RSA1.pub[1]; L_n = len(n_h)
    n_0 = (L_n - len(a))
    a = ("0" * n_0) + a
    c_chk = long(RSA1.encrypt(a.decode("hex")), 16)
    if c_chk == c: return True
    return False

def U_of_M(M, M_chk):
    M.append(M_chk)
    for i in range (len(M) - 1):
        for j in range (i + 1, len(M)):
            (a, b) = M[i]; (x, y) = M[j]
            if (((x <= a) and (y > (a - 2))) or
                ((x < (b + 2)) and (y >= b))):
                M[i] = (min(a, x), max(b, y))
                del M[j]
                i = 0; j = 1
    return M

def I_of_M(M, M_new):
    M_I = []; i = 0; j = 0
    for i in range (len(M)):
        for j in range (len(M_new)):
            (a, b) = M[i]; (x, y) = M_new[j]
            if ((a <= y <= b) or (x <= b <= y)):
                M_I = U_of_M(M_I, (max(a, x), min(b, y)))
    return M_I

def bb_2a(c):
    print "2A"
    N = RSA1.pub[1]; e = RSA1.pub[0]
    B = 2 ** (RSA1.b - 16)
    s1 = divC(N, 3*B)
    print "\rs:", s1,

    while True:
        for i in range (100):
            cs1 = (c * pow(s1, e, N)) % N
            if RSA1.oracle(cs1): return s1
            s1 += 1
        print "\rs:", s1,

def bb_2b(c, s):
    print "2B"
    N = RSA1.pub[1]; e = RSA1.pub[0]
    while True:
        for i in range (100):
            s += 1
            cs = (c * pow(s, e, N)) % N
            if RSA1.oracle(cs): return s
        print "\rs:", s,

def bb_2c(c, s, M):
    print "2C"
    N = RSA1.pub[1]; e = RSA1.pub[0]
    B = 2 ** (RSA1.b - 16)

    (a, b) = M[0]

    r = divC(2 * (b * s - 2 * B), N)
    while True:
        for s in range ((2*B + r*N) / b,
                        ((3*B + r*N) / a) + 1):
            cs = (c * pow(s, e, N)) % N
            if RSA1.oracle(cs): return s
        r += 1

def bb_3(s, M):
    N = RSA1.pub[1]
    B = 2 ** (RSA1.b - 16)
    M_new = []

    for i in range (len(M)):
        a = M[i][0]; b = M[i][1]
        rF = divC((a*s) - (3*B) + 1, N)
        rC = divF((b*s) - (2*B), N)
        if rF > rC: rF -= 1

        for r in range (rF, rC + 1):
            M_chk = (max(a, divC((2*B) + (r*N), s)),
                     min(b, divF((3*B) + (r*N) - 1, s)))
            M_new = U_of_M(M_new, sorted(M_chk))

    M_I = I_of_M(M, M_new); return M_I

def bb_98():
    m = RSA1.pad("kick it, CC".encode("hex"))
    print m
    ct = RSA1.encrypt(m.decode("hex"))
    print "ct:", ct
    c = long(ct, 16)

    N = RSA1.pub[1]
    B = 2 ** (RSA1.b - 16)

    M0 = [(2 * B, 3*B - 1)]; M = M0
    print "\n\nM:"
    for i in range (len(M)):
        print "(%x" % M[i][0]
        print " %x)" % M[i][1]

    s = bb_2a(c)

    while True:
        M = bb_3(s, M)

        i = 0
        while i < len(M):
            a = M[i][0]; b = M[i][1]
            if a == b:
                if check(a, c):
                    print "\nM:"
                    for i in range (len(M)):
                        print "(%x" % M[i][0]
                        print " %x)" % M[i][1]
                    return a
                else:
                    del M[i]
                    i -= 1
            i += 1

        print "\nM:"
        for i in range (len(M)):
            print "(%x" % M[i][0]
            print " %x)" % M[i][1]

        if len(M) > 1:
            s = bb_2b(c, s)
        else:
            s = bb_2c(c, s, M)

        print "\rs:", s,

#######################################################################
# Main routine
if __name__ == "__main__":
    print "\nInitializing RSA..."
    bits = 768
    RSA1 = RSA(bits); print ""

    a = bb_98()
    a = "%x" % a
    if len(a) % 2: a = "0" + a

    n_h = "%x" % RSA1.pub[1]; L_n = len(n_h)
    n_0 = (L_n - len(a))
    a = ("0" * n_0) + a
    a = a.decode("hex")
    print "\n\n\na:", a

    print " " * 80, "\n"
