import array
import base64
from Crypto.Cipher import AES
from random import randint

############################################################
# generate random key, also provide key for given text
def gen_key():
    key = array.array('B', [])

    for i in range (0, 16):
        key.append(randint(0,255))

    return key.tostring()

class Key(object):
    def __init__(self):
        self.ey_YS = "YELLOW SUBMARINE"
        self.ey = ""
K = Key()
K.ey = gen_key()

############################################################
# open text file, decode with key expressed above
class TextFiles(object):
    def __init__(self):
        self.ext = ""
T = TextFiles()

def open_text_file():
    fname = "CP4_25.txt"
    orig = open(fname).read()
    T.ext = base64.b64decode(orig)
    decryptor = AES.new(K.ey_YS, AES.MODE_ECB)
    T.ext = decryptor.decrypt(T.ext)
open_text_file()

############################################################
# code for running CTR with a random key
def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)

    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]

    return a3.tostring()

def CTR_transform(text):
    N = len(text) / 16
    if len(text) % 16 != 0: N += 1

    new_text = ""
    encryptor = AES.new(K.ey, AES.MODE_ECB)

    for i in range (0, N):
        stream_text = '\x00'*8 + chr(i) + '\x00'*7
        KSblock = encryptor.encrypt(stream_text)

        if i < N-1: PTblock = text[i*16:(i+1)*16]
        else: PTblock = text[i*16:]

        text_to_add = strxor(PTblock, KSblock)

        new_text = new_text + text_to_add

    return new_text

############################################################
# replace plaintext funtion
def edit(ct, offset, newtext):
    pt = CTR_transform(ct)

    if offset + len(newtext) >= len(pt):
        newpt = pt[0: offset] + newtext
    else:
        newpt = (pt[0: offset] + newtext +
                 pt[offset + len(newtext):])

    newtext = CTR_transform(newpt)

    return newtext

############################################################

def test_edit():
    print "\n"
    ct = CTR_transform(T.ext)
    altered_ct = edit(ct, 4, "lame")
    altered_pt = CTR_transform(altered_ct)
    print altered_pt
    print "\n"

def exploit_edit():
    print "\n"
    ct = CTR_transform(T.ext)
    pt_as_ct = edit(ct, 0, ct)
    print pt_as_ct
    print "\n"
exploit_edit()
