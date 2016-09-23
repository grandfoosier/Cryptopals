import array
from Crypto.Cipher import AES
from random import randint
import re

############################################################
# set text
class TextFiles(object):
    def __init__(self):
        self.ext1 = ""
        self.ext2 = ""
T = TextFiles()
def set_text():
    #         0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    T.ext1 = "comment1=cooking%20MCs;userdata="
    T.ext2 = ";comment2=%20like%20a%20pound%20of%20bacon"
    T.extA = "xxxxx:admin<true"
    #   32 +       5     11
set_text()

############################################################
# generate random key
def gen_key():
    key = array.array('B', [])

    for i in range (0, 16):
        key.append(randint(0,255))

    return key.tostring()

class Key(object):
    def __init__(self):
        self.ey = ""
        self.IV = ""
K = Key()
K.ey = gen_key()

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
    cipher = AES.new(K.ey, AES.MODE_ECB)

    for i in range (0, N):
        stream_text = '\x00'*8 + chr(i) + '\x00'*7
        KSblock = cipher.encrypt(stream_text)

        if i < N-1: PTblock = text[i*16:(i+1)*16]
        else: PTblock = text[i*16:]

        text_to_add = strxor(PTblock, KSblock)

        new_text = new_text + text_to_add

    return new_text

############################################################
# look for (admin, true) tuple
def check_for_admin(tuples):
    Admin = False

    for i in range (0, len(tuples)):
        if tuples[i][0] == "admin":
            Admin = (tuples[i][1] == "true")

    return Admin

############################################################
#  prepend+append text, encrypt new string
def F_1_encrypt(text):
    stripped_text = re.sub('[;=]', '', text)
    text_to_encrypt = T.ext1 + stripped_text + T.ext2
    new_text = CTR_transform(text_to_encrypt)

    return new_text

############################################################
#  decrypt and make tuples: A = B; => (A, B)
def F_2_decrypt(text):
    s = CTR_transform(text)

    SCs = [pos for pos, char in enumerate(s) if char == ';']
    tuples = []
    text_bite = s[:SCs[0]]
    Es = [pos for pos, char in enumerate(text_bite) if char == '=']

    if len(Es) == 0:
        tuples.append([0,text_bite])
    else:
        tuples.append([text_bite[:Es[0]],text_bite[Es[0]+1:]])

    for i in range (0, len(SCs) - 1):
        text_bite = s[SCs[i]+1:SCs[i+1]]
        Es = [pos for pos, char in enumerate(text_bite) if char == '=']

        if len(Es) == 0:
            tuples.append([0,text_bite])
        else:
            tuples.append([text_bite[:Es[0]],text_bite[Es[0]+1:]])

    text_bite = s[SCs[-1]+1:]
    Es = [pos for pos, char in enumerate(text_bite) if char == '=']

    if len(Es) == 0:
        tuples.append([0,text_bite])
    else:
        tuples.append([text_bite[:Es[0]],text_bite[Es[0]+1:]])

    Admin = check_for_admin(tuples)
    print Admin

    return s

############################################################
#  bitflipping function
def convert():
    str_0 = F_1_encrypt(T.extA)

    str_1 = (str_0[:37] + chr(ord(str_0[37]) ^ ord(":") ^ ord(";"))
           + str_0[38:])

    str_2 = (str_1[:43] + chr(ord(str_1[43]) ^ ord("<") ^ ord("="))
           + str_1[44:])

    new_text = F_2_decrypt(str_2)

    print ""
    print new_text
    print ""

print ""
convert()
print ""
