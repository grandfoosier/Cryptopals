import base64
import array
import struct
from random import randint

#######################################################################
# set text
class TextFiles(object):
    def __init__(self):
        self.ext = (b'comment1=cooking%20MCs;userdata=foo;' +
                    b'comment2=%20like%20a%20pound%20of%20bacon')
        self.ip =   b';admin=true'
T = TextFiles()

#######################################################################
# generate random key
def gen_key():
    key = ""
    l = randint(3, 13)

    for i in range (0, l):
        key = key + chr(randint(97, 122))

    return key
class Key(object):
    def __init__(self):
        self.ey = gen_key()
K = Key()

#######################################################################
# MD4 in code
class MD4x(object):
    h0_0 = 0x67452301; h1_0 = 0xEFCDAB89
    h2_0 = 0x98BADCFE; h3_0 = 0x10325476;

    def __init__(self, text, h0 = h0_0, h1 = h1_0,
                 h2 = h2_0, h3 = h3_0, ml = None):
        self.h0 = h0; self.h1 = h1
        self.h2 = h2; self.h3 = h3
        self.X = []

        text_array = bytearray(text)

        if ml == None: ml = len(text_array) * 8

        text_array = self._pad(text_array, ml)
        self.hh = self._hash(text_array)

    def _pad(self, text_array, ml):
        text_array.append(0x80)
        text_array.extend([0] *
                          ((56 - (len(text_array) % 64)) % 64))
        text_array.extend(struct.pack('<Q', ml))

        return text_array

    def _lefrot(self, n, b):
        return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

    def _f(self, x, y, z): return (x & y) | (~x & z)
    def _g(self, x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(self, x, y, z): return x ^ y ^ z

    def _r1(self, a, b, c, d, k, s):
        return self._lefrot(a + self._f(b, c, d) +
            self.X[k], s)
    def _r2(self, a, b, c, d, k, s):
        return self._lefrot(a + self._g(b, c, d) +
            self.X[k] + 0x5A827999, s)
    def _r3(self, a, b, c, d, k, s):
        return self._lefrot(a + self._h(b, c, d) +
            self.X[k] + 0x6ED9EBA1, s)

    def _hash(self, text_array):
        for i in range (0, len(text_array), 64):
            self.X = [0] * 16
            a = self.h0; b = self.h1; c = self.h2; d = self.h3

            for j in range (0, 64, 4):
                self.X[j/4] = struct.unpack('<L',
                    text_array[i+j: i+j+4])[0]

            a = self._r1(a,b,c,d, 0, 3); d = self._r1(d,a,b,c, 1, 7)
            c = self._r1(c,d,a,b, 2,11); b = self._r1(b,c,d,a, 3,19)
            a = self._r1(a,b,c,d, 4, 3); d = self._r1(d,a,b,c, 5, 7)
            c = self._r1(c,d,a,b, 6,11); b = self._r1(b,c,d,a, 7,19)
            a = self._r1(a,b,c,d, 8, 3); d = self._r1(d,a,b,c, 9, 7)
            c = self._r1(c,d,a,b,10,11); b = self._r1(b,c,d,a,11,19)
            a = self._r1(a,b,c,d,12, 3); d = self._r1(d,a,b,c,13, 7)
            c = self._r1(c,d,a,b,14,11); b = self._r1(b,c,d,a,15,19)

            a = self._r2(a,b,c,d, 0, 3); d = self._r2(d,a,b,c, 4, 5)
            c = self._r2(c,d,a,b, 8, 9); b = self._r2(b,c,d,a,12,13)
            a = self._r2(a,b,c,d, 1, 3); d = self._r2(d,a,b,c, 5, 5)
            c = self._r2(c,d,a,b, 9, 9); b = self._r2(b,c,d,a,13,13)
            a = self._r2(a,b,c,d, 2, 3); d = self._r2(d,a,b,c, 6, 5)
            c = self._r2(c,d,a,b,10, 9); b = self._r2(b,c,d,a,14,13)
            a = self._r2(a,b,c,d, 3, 3); d = self._r2(d,a,b,c, 7, 5)
            c = self._r2(c,d,a,b,11, 9); b = self._r2(b,c,d,a,15,13)

            a = self._r3(a,b,c,d, 0, 3); d = self._r3(d,a,b,c, 8, 9)
            c = self._r3(c,d,a,b, 4,11); b = self._r3(b,c,d,a,12,15)
            a = self._r3(a,b,c,d, 2, 3); d = self._r3(d,a,b,c,10, 9)
            c = self._r3(c,d,a,b, 6,11); b = self._r3(b,c,d,a,14,15)
            a = self._r3(a,b,c,d, 1, 3); d = self._r3(d,a,b,c, 9, 9)
            c = self._r3(c,d,a,b, 5,11); b = self._r3(b,c,d,a,13,15)
            a = self._r3(a,b,c,d, 3, 3); d = self._r3(d,a,b,c,11, 9)
            c = self._r3(c,d,a,b, 7,11); b = self._r3(b,c,d,a,15,15)

            self.h0 = self.h0 + a & 0xffffffff
            self.h1 = self.h1 + b & 0xffffffff
            self.h2 = self.h2 + c & 0xffffffff
            self.h3 = self.h3 + d & 0xffffffff

        return struct.pack('<IIII', self.h0, self.h1, self.h2, self.h3)

    def digest(self):
        return self.hh

    def hexdigest(self):
        return self.hh.encode("hex")

    def digest64(self):
        return base64.b64encode(self.hh)

#######################################################################
# test MD4 code
def check(msg, sig):
	m = MD4x(msg)
	print m.hexdigest() == sig
def run_tests():
    check("", '31d6cfe0d16ae931b73c59d7e0c089c0')
    check("a", 'bde52cb31de33e46245e05fbdbd6fb24')
    check("abc", 'a448017aaf21d8525fc10ae87aa6729d')
    check("message digest",
    		'd9130a8164549fe818874806e1c7014b')
    check("abcdefghijklmnopqrstuvwxyz",
    		'd79e1c308aa5bbcdeea8ed63df412da9')
    check("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" +
          "ghijklmnopqrstuvwxyz0123456789",
    		'043f8582f241db351ce627e153e7f0e4')
    check("12345678901234567890123456789012" +
          "34567890123456789012345678901234" +
          "5678901234567890",
    		'e33b4ddc9c38f2199c3e7b164fcc0536')
# run_tests()

#######################################################################
# same padding function as MD4
def MD4pad(text):
    text_array = bytearray(text)
    ml = len(text_array) * 8
    text_array.append(0x80)
    text_array.extend([0] *
                      ((56 - (len(text_array) % 64)) % 64))
    text_array.extend(struct.pack('<Q', ml))

    return text_array

#######################################################################
# validate that text really produces MAC
def validate(text, MAC):
    return MD4x(K.ey + text).digest64() == MAC

#######################################################################
# get desired MAC, registers
class Registers(object):
    def __init__(self):
        MAC = MD4x(K.ey + T.ext).digest()
        self.eg = struct.unpack('<4I', bytearray(MAC))
R = Registers()

#######################################################################
# guess key length until you find it
def try_lengths():
    for i in range (0, 100):
        forgedtext = MD4pad(("A" * i) + T.ext)[i:] + T.ip

        ml = (len(forgedtext) + i) * 8
        forgedMAC = MD4x(T.ip, R.eg[0], R.eg[1], R.eg[2],
                         R.eg[3], ml).digest64()

        if validate(forgedtext, forgedMAC):
            print "Admin access granted\n"
            print forgedtext
            print forgedMAC

            return (forgedtext, forgedMAC)

    print "Forgery failed."
    return 0

print ""
try_lengths()
print "\n"
