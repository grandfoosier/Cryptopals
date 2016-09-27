import array
from Crypto.Cipher import AES
from random import randint
import re

############################################################
# set text
class TextFiles(object):
    def __init__(self):
        pass
T = TextFiles()
def set_text():
    #         0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    T.ext1 = "comment1=cooking%20MCs;userdata="
    T.ext2 = ";comment2=%20like%20a%20pound%20of%20bacon"
    T.extA = "0123456789ABCDEF"
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
K = Key()
K.ey = gen_key()

############################################################
# set cipher
class Cipher(object):
    def __init__(self):
        self.fr = ""
X = Cipher()
X.fr = AES.new(K.ey, AES.MODE_ECB)

############################################################
# setup functions for CBC
def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)

    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]

    return a3.tostring()

def PKCS7(text):
    raw_N = len(text)
    full_blocks = raw_N / 16
    Nbytes = 16 - (raw_N - (full_blocks * 16))
    text_array = array.array('B', text)
    N = len(text_array)

    for i in range (0, Nbytes):
        text_array.append(Nbytes)

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

def XOR_ECB(block1, block2):
    combined_text = strxor(block1, block2)

    new_text = X.fr.encrypt(combined_text)

    return new_text

def ECB_XOR(block1, block2):
    decrypted_text = X.fr.decrypt(block2.tostring())

    new_text = strxor(block1, decrypted_text)

    return new_text

############################################################
# code for running CBC with a random key; IV == key
def CBC_encrypt(text):
    text_array = array.array('B', PKCS7(text))

    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])
    block_array = array.array('B', XOR_ECB(K.ey, text_array[0:16]))

    for i in range (0, 16):
        new_text_array.append(block_array[i])

    for i in range (1, Nblocks):
        block_array = array.array('B', XOR_ECB(
            new_text_array[((i-1)*16):(i*16)],
            text_array[(i*16):((i+1)*16)]))

        for j in range (0, 16):
            new_text_array.append(block_array[j])

    new_text = new_text_array.tostring()
    return new_text

def CBC_decrypt(text):
    text_array = array.array('B', text)

    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])
    block_array = array.array('B', ECB_XOR(K.ey, text_array[0:16]))

    for j in range (len(block_array)):
        new_text_array.append(block_array[j])

    for i in range (1, Nblocks):
        block_array = array.array('B', ECB_XOR(
            text_array[((i - 1) * 16): (i * 16)],
            text_array[(i * 16): ((i + 1) * 16)]))

        for j in range (len(block_array)):
            new_text_array.append(block_array[j])

    new_text = new_text_array.tostring()
    return new_text

############################################################
#  prepend+append text, encrypt new string
def F_1_encrypt(text):
    stripped_text = re.sub('[;=]', '', text)
    text_to_encrypt = T.ext1 + stripped_text + T.ext2
    new_text = CBC_encrypt(text_to_encrypt)

    return new_text

############################################################
#  check for ASCII compliance
def verify_compliance(CT):
    text = CBC_decrypt(CT)

    for i in range (0, len(text)):
        if ord(text[i]) >= 128:
            print "\nERROR\n"
            print text + "\n"
            return text

    print "ok"
    return "ok"

############################################################
#  modify CT (attack), C1, C2, C3 => C1, 0, C1
def modify_ct(text):
    text = text[0: 16] + chr(0) * 16 + text[0: 16]
    return text

############################################################
#  decrypt, recover PT, extract key
def extract_key():
    CT = F_1_encrypt(T.extA)

    CT_mod = modify_ct(CT)

    PT_comp = verify_compliance(CT_mod)

    if PT_comp != "ok":
        key = strxor(PT_comp[0: 16], PT_comp[32: 48])

        return key

    return 0

print ""
key = extract_key()
print str(array.array('B', key))[11:-1]
print key == K.ey
print "\n"
