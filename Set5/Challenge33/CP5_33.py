from hashlib import sha256
from random import randint
import array

#######################################################################
# Bignum given from challenge
class Bignum(object):
    def __init__(self):
        self.ig = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

#######################################################################
# Create a key given inputs p and g
def dh_key(p, g):
    a = randint(0, p-1); b = randint(0, p-1)
    A = pow(g, a, p); B = pow(g, b, p)
    s = pow(B, a, p); assert s == pow(A, b, p)

    h = hex(s)[2:]
    if h[-1] == b'L': h = h[: -1]
    if len(h) % 2: h = "0" + h
    bh = bytearray.fromhex(h)

    keyEh = sha256(bh).hexdigest()[: 32]
    keyMh = sha256(bh).hexdigest()[32: ]

    print keyEh, keyMh

    return keyEh, keyMh

#######################################################################
# Main routine
if __name__ == "__main__":
    B = Bignum()

    print ""
    print "37, 5:"
    keyE, keyM = dh_key(37, 5)
    print ""

    print "big, 2:"
    keyE, keyM = dh_key(B.ig, 2)
    print "\n"
