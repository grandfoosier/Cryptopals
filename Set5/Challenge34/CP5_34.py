from hashlib import sha1
from random import randint
from Crypto.Cipher import AES
import array

#######################################################################
# Setup
class Bignum(object):
    def __init__(self):
        self.ig = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

class Role(object):
    def __init__(self):
        pass

def gen_key():
    key = array.array('B', [])
    for i in range (0, 16): key.append(randint(0,255))
    return key

#######################################################################
# AES-CBC code
def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)
    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]
    return a3.tostring()

def PKCS7(text, pad):
    text_array = array.array('B', text)
    N = len(text_array)
    for i in range (0, pad):
        text_array.append(pad)
    padded_text = text_array.tostring()
    return padded_text

def unPKCS7(text):
    pad = ord(text[-1])
    assert len(text) > pad
    check = 0

    for i in range (0, pad):
        if ord(text[-1 - i]) == pad:
            check += 1

    assert check == pad
    new_text = text[0:pad * -1]
    return new_text

def XOR_ECB(block1, block2, encryptor):
    combined_text = strxor(block1, block2)
    new_text = encryptor.encrypt(combined_text)
    return new_text

def ECB_XOR(block1, block2, decryptor):
    decrypted_text = decryptor.decrypt(block2.tostring())
    new_text = strxor(block1, decrypted_text)
    return new_text

def CBC_encrypt(encryptor, IV, text):
    raw_N = len(text)
    full_blocks = raw_N / 16
    Nbytes = 16 - (raw_N - (full_blocks * 16))
    text_array = array.array('B', PKCS7(text, Nbytes))

    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])

    block_array = array.array('B',
                XOR_ECB(IV, text_array[0: 16], encryptor))
    for i in range (0, 16):
        new_text_array.append(block_array[i])

    for i in range (1, Nblocks):
        block_array = array.array('B', XOR_ECB(
            new_text_array[((i - 1) * 16): (i * 16)],
            text_array[(i * 16): ((i + 1) * 16)], encryptor))
        for j in range (0, 16):
            new_text_array.append(block_array[j])

    return new_text_array

def CBC_decrypt(decryptor, IV, text):
    text_array = array.array('B', text)
    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])

    for i in range (0, Nblocks - 1):
        j = Nblocks - i
        block_array = array.array('B', ECB_XOR(
            text_array[((j - 2) * 16): ((j - 1) * 16)],
            text_array[((j - 1) * 16): (j * 16)], decryptor))
        for k in range (0, 16):
            new_text_array.insert(0, block_array[15 - k])

    block_array = array.array('B',
                ECB_XOR(IV, text_array[0: 16], decryptor))
    for j in range (0, 16):
        new_text_array.insert(0, block_array[15 - j])

    pad_text = new_text_array.tostring()
    new_text = unPKCS7(pad_text)

    return new_text

#######################################################################
# A's functions
def a1():
    Ar.msg = "foo"
    Ar.p = X.ig; Ar.g = 2
    Ar.a = randint(0, Ar.p-1); Ar.A = pow(Ar.g, Ar.a, Ar.p)
    return Ar.p, Ar.g, Ar.A

def a2(B):
    Ar.B = B
    s = pow(Ar.B, Ar.a, Ar.p)
    h = hex(s)[2:]
    if h[-1] == b'L': h = h[: -1]
    if len(h) % 2: h = "0" + h
    bh = bytearray.fromhex(h)

    Ar.key = sha1(bh).digest()[: 16]
    Ar.enc = AES.new(Ar.key, AES.MODE_ECB)
    Ar.ivA = gen_key()

    a_sends = bytearray(CBC_encrypt(Ar.enc, Ar.ivA, Ar.msg).tostring())
    a_sends += bytearray(Ar.ivA.tostring())
    return a_sends

def a3(b_sends):
    b_msg = b_sends[: -16]
    Ar.ivB = b_sends[-16: ]

    unenc = CBC_decrypt(Ar.enc, Ar.ivB, b_msg)
    return unenc == Ar.msg

#######################################################################
# B's functions
def b1(p, g, A):
    Br.p = p; Br.g = g; Br.A = A
    Br.b = randint(0, Br.p-1); Br.B = pow(Br.g, Br.b, Br.p)
    return Br.B

def b2(a_sends):
    s = pow(Br.A, Br.b, Br.p)
    h = hex(s)[2:]
    if h[-1] == b'L': h = h[: -1]
    if len(h) % 2: h = "0" + h
    bh = bytearray.fromhex(h)

    Br.key = sha1(bh).digest()[: 16]
    Br.enc = AES.new(Br.key, AES.MODE_ECB)
    Br.ivB = gen_key()

    a_msg = a_sends[: -16]
    Br.ivA = a_sends[-16: ]

    unenc = CBC_decrypt(Br.enc, Br.ivA, a_msg)

    b_sends = bytearray(CBC_encrypt(Br.enc, Br.ivB, unenc).tostring())
    b_sends += bytearray(Br.ivB.tostring())
    return b_sends

#######################################################################
# normal and hacked
def norm_proc():
    print "NORMAL:\n"
    p, g, A = a1()
    print "Party A sends p, g, A to Party B\n"
    B = b1(p, g, A)
    print "Party B sends B to Party A\n"
    a_sends = a2(B)
    print "Party A sends encrypted message (foo) to Party B:"
    print a_sends, "\n"
    b_sends = b2(a_sends)
    print "Party B decrypts A's message, reencrypts and sends it back:"
    print b_sends, "\n"
    a_checks = a3(b_sends)
    print "Party A decrypts B's message and verifies it is the same:"
    print a_checks, "\n"

def hack_proc():
    print "HACKED:\n"
    p, g, A = a1()
    print "Party A sends p, g, A to Party B"
    print "We intercept, send p, g, p to B\n"
    B = b1(p, g, p)
    print "Party B sends B to Party A"
    print "We intercept, send p to A\n"
    a_sends = a2(p)
    print "Party A sends encrypted message (foo) to Party B:"
    print a_sends, "\n"

    bh = bytearray.fromhex("00")
    Mkey = sha1(bh).digest()[: 16]
    Menc = AES.new(Mkey, AES.MODE_ECB)
    a_msg = a_sends[: -16]
    MivA = a_sends[-16: ]
    unenc = CBC_decrypt(Menc, MivA, a_msg)
    print "We can decrypt this since we know what the key is (0):"
    print unenc, "\n"

    b_sends = b2(a_sends)
    print "Party B decrypts A's message, reencrypts and sends it back:"
    print b_sends, "\n"

    b_msg = b_sends[: -16]
    MivB = b_sends[-16: ]
    unenc = CBC_decrypt(Menc, MivB, b_msg)
    print "We can decrypt this since it uses the same known key:"
    print unenc, "\n"

    a_checks = a3(b_sends)
    print "Party A decrypts B's message and verifies it is the same:"
    print a_checks, "\n"

#######################################################################
# Main routine
if __name__ == "__main__":
    X = Bignum()
    Ar = Role(); Br = Role(); Mr = Role()
    print ""
    norm_proc()
    print ""
    hack_proc()
    print "\n"
