from hashlib import sha1
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
# SHA1 in code
class SHA1x(object):
    h0_0 = 0x67452301; h1_0 = 0xEFCDAB89; h2_0 = 0x98BADCFE
    h3_0 = 0x10325476; h4_0 = 0xC3D2E1F0

    def __init__(self, text, h0 = h0_0, h1 = h1_0, h2 = h2_0,
                 h3 = h3_0, h4 = h4_0, ml = None):
        self.h0 = h0; self.h1 = h1; self.h2 = h2
        self.h3 = h3; self.h4 = h4

        text_array = bytearray(text)

        if ml == None: ml = len(text_array) * 8

        text_array = self._pad(text_array, ml)
        self.hh = self._hash(text_array)

    def _pad(self, text_array, ml):
        text_array.append(0x80)
        text_array.extend([0] *
                          ((56 - (len(text_array) % 64)) % 64))
        text_array.extend(struct.pack('>Q', ml))

        return text_array

    def _lefrot(self, n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    def _hash(self, text_array):
        for chunk in range (0, len(text_array), 64):
            w = list(struct.unpack('>16L',
                                   text_array[chunk: chunk + 64]))

            for i in range(16, 80):
                w.append(self._lefrot((w[i - 3] ^ w[i - 8] ^
                                 w[i - 14] ^ w[i - 16]), 1))

            a, b, c, d, e = (self.h0, self.h1, self.h2,
                             self.h3, self.h4)

            for i in range(0, 80):
                if 0 <= i < 20:
                    f = (b & c) | ((~b) & d); k = 0x5A827999
                elif 20 <= i < 40:
                    f = b ^ c ^ d; k = 0x6ED9EBA1
                elif 40 <= i < 60:
                    f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
                elif 60 <= i < 80:
                    f = b ^ c ^ d; k = 0xCA62C1D6

                a, b, c, d, e = (self._lefrot(a, 5) + f + e + k +
                                 w[i] & 0xffffffff, a,
                                 self._lefrot(b, 30), c, d)

            self.h0 = self.h0 + a & 0xffffffff
            self.h1 = self.h1 + b & 0xffffffff
            self.h2 = self.h2 + c & 0xffffffff
            self.h3 = self.h3 + d & 0xffffffff
            self.h4 = self.h4 + e & 0xffffffff

        return '%08x%08x%08x%08x%08x' % (self.h0, self.h1, self.h2,
                                         self.h3, self.h4)

    def digest(self):
        return self.hh.decode("hex")

    def hexdigest(self):
        return self.hh

    def digest64(self):
        return base64.b64encode(self.hh.decode("hex"))

#######################################################################
# same padding function as SHA1
def SHA1pad(text):
    text_array = bytearray(text)
    ml = len(text_array) * 8
    text_array.append(0x80)
    text_array.extend([0] *
                      ((56 - (len(text_array) % 64)) % 64))
    text_array.extend(struct.pack('>Q', ml))

    return text_array

#######################################################################
# validate that text really produces MAC
def validate(text, MAC):
    return SHA1x(K.ey + text).digest64() == MAC

#######################################################################
# get desired MAC, registers
class Registers(object):
    def __init__(self):
        MAC = SHA1x(K.ey + T.ext).digest()
        self.eg = struct.unpack('>5I', bytearray(MAC))
R = Registers()

#######################################################################
# guess key length until you find it
def try_lengths():
    for i in range (0, 100):
        forgedtext = SHA1pad(("A" * i) + T.ext)[i:] + T.ip

        ml = (len(forgedtext) + i) * 8
        forgedMAC = SHA1x(T.ip, R.eg[0], R.eg[1], R.eg[2],
                          R.eg[3], R.eg[4], ml).digest64()

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
