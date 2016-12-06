from Crypto.Util.number import getPrime
from hashlib import sha1
from sympy import integer_nthroot

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
            p = getPrime(self.b); q = getPrime(self.b)
            n = p * q; et = (p - 1) * (q - 1)
            print "..."
        d = self._invmod(e, et)
        self.pub = [e, n]; self.prv = [d, n]

    def __init__(self, b):
        self.b = b
        self._mk_keys()

    def encrypt(self, pt):                               # S
        m = int(pt.encode("hex"), 16)                    # H -> I
        cti = pow(m, self.pub[0], self.pub[1])
        ct = "%x" % cti                                  # H
        if len(ct) % 2: ct = "0" + ct
        return ct

    def decrypt(self, ct):                               # H
        m = pow(long(ct, 16), self.prv[0], self.prv[1])  # I
        pt = "%x" % m                                    # H
        if len(pt) % 2: pt = "0" + pt
        return pt.decode("hex")                          # S

#######################################################################
# Sign and Validate (poorly)
def PKCS1_5_sign(msg):                                   # S
    n_h = "%x" % RSA1.pub[1]; L_n = len(n_h)
    n_ff = (L_n - (4 + 2 + 30 + 40) + (L_n % 2)) / 2

    dig = ("0001" + ("ff" * n_ff) + "00" +
           "3021300906052b0e03021a05000414" +
           sha1(msg).hexdigest())                        # H

    sig = RSA1.decrypt(dig).encode("hex")                # S -> H
    print "sig:     ", sig; return sig

def bad_valid(sig):                                      # H
    sig_u = RSA1.encrypt(sig.decode("hex"))              # S -> H

    n_h = "%x" % RSA1.pub[1]; L_n = len(n_h)
    n_0 = (L_n - len(sig_u))
    dig = ("0" * n_0) + sig_u
    print "digest:  ", dig

    if dig[0: 6] != "0001ff": return False
    i = 2
    while dig[i * 2: i * 2 + 2] == "ff": i += 1
    if dig[i * 2: i * 2 + 32] != "003021300906052b0e03021a05000414":
        return False
    if len(dig) < i * 2 + 72: return False
    return True                                          # T/F

#######################################################################
# Construct a false signature
def forge_sig(msg):                                      # S
    n_h = "%x" % RSA1.pub[1]; L_n = len(n_h)
    msg_hash = sha1(msg).hexdigest()                     # H
    dig = ("0001ff003021300906052b0e03021a05000414" +
             msg_hash + ("00" * ((L_n / 2) - 39)))
    print "digest:  ", dig

    cube_root, V = integer_nthroot(int(dig, 16), 3)      # I
    sig_F = "%x" % (cube_root + 1)                       # H
    if len(sig_F) % 2: sig_F = "0" + sig_F
    print "sig_F:   ", sig_F; return sig_F

#######################################################################
# Main routine
if __name__ == "__main__":
    RSA1 = RSA(1024)

    print "\nhi mom\n"

    print "\nNORMAL:\n"
    sig = PKCS1_5_sign("hi mom")
    print ""
    val = bad_valid(sig)
    print "\nValid:   ", val, "\n"

    print "\nHACKED:\n"
    sig_F = forge_sig("hi mom")
    print ""
    val = bad_valid(sig_F)
    print "\nValid:   ", val, "\n"
