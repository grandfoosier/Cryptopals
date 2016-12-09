from Crypto.Util.number import getPrime
from hashlib import sha1
from math import log
from random import choice
from sympy import integer_nthroot
import base64

#######################################################################
# RSA class and functions (w parity check)
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
        print ("[e, n]: [" + str(self.pub[0]) + ", \n" +
               "%x" % self.pub[1] + "]")

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

    def parity(self, ct):                                # H
        pt = self.decrypt(ct)                            # S
        P = int(pt.encode("hex"), 16) % 2; return P      # I

#######################################################################
# Decrypt a cyphertext by multiplying by encoded numbers
def decrypt_w_parity(ct, b, L):
    N = RSA1.pub[1]
    N_l = 0; N_u = RSA1.pub[1] - 1; D = (N_u + N_l) / 2

    ctI = long(ct, 16)
    M = pow(2, RSA1.pub[0], N)
    i = 1

    escapes = ''.join([chr(char) for char in range(1, 32)])

    while (N_u - N_l) > 3:
        ctI = (ctI * M) % N; ctH = "%x" % ctI
        if len(ctH) % 2: ctH = "0" + ctH
        P = RSA1.parity(ctH)
        N_u -= D * (1 - P); N_l += D * P
        D = (N_u - N_l) / 2
        ptu = "%x" % N_u
        if len(ptu) % 2: ptu = "0" + ptu
        print ("\r%i%%, %s                    " % (
            (i * 100) / (b * 2),
            ptu.decode("hex").translate(None,
                escapes)[: L + 20])),
        i += 1

    j = 0
    while True:
        pti = "%x" % ((N_u + N_l) / 2 + j)
        if len(pti) % 2: pti = "0" + pti
        pt = pti.decode("hex")
        if RSA1.encrypt(pt) == ct: return pt
        j = (j * -1) + 1
        pti = "%x" % ((N_u + N_l) / 2 + j)
        if len(pti) % 2: pti = "0" + pti
        pt = pti.decode("hex")
        if RSA1.encrypt(pt) == ct: return pt
        j *= -1


#######################################################################
# Main routine
if __name__ == "__main__":
    print "\nInitializing RSA..."
    b = 1024
    RSA1 = RSA(b); print ""

    # msg = "hi mom"; print msg, "\n"
    # ct = RSA1.encrypt(msg); print "ct:\n" + ct + "\n"
    # msg = decrypt_w_parity(ct, b, len(msg))
    # print "\r", msg, "  " * 80, "\n"
    # pause = raw_input("")

    secret = ("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFy" +
              "b3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
    secret = base64.b64decode(secret)
    ct = RSA1.encrypt(secret); print "ct:\n" + ct + "\n"
    msg = decrypt_w_parity(ct, b, len(secret))
    print "\r", msg, "  " * 80, "\n"
