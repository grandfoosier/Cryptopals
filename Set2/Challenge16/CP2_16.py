import array
from Crypto.Cipher import AES
from random import randint
import re

mode = AES.MODE_ECB

class TextFiles(object):
    def __init__(self):
        self.ext1 = ""
        self.ext2 = ""
T = TextFiles()
#         0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
T.ext1 = "comment1=cooking%20MCs;userdata="
T.ext2 = ";comment2=%20like%20a%20pound%20of%20bacon"
T.extA = "_____!_____!____xxxxx:admin<true"
#   32 +       5     11

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
K.IV = gen_key()

encryptor = AES.new(K.ey, mode)
decryptor = AES.new(K.ey, mode)

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

    new_text = encryptor.encrypt(combined_text)

    return new_text

def ECB_XOR(block1, block2):
    decrypted_text = decryptor.decrypt(block2.tostring())

    new_text = strxor(block1, decrypted_text)

    return new_text

def CBC_encrypt(text):
    text_array = array.array('B', PKCS7(text))

    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])
    block_array = array.array('B', XOR_ECB(K.IV, text_array[0:16]))

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

    block_array = array.array('B', ECB_XOR(K.IV, text_array[0:16]))

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

def check_for_admin(tuples):
    Admin = False

    for i in range (0, len(tuples)):
        if tuples[i][0] == "admin":
            Admin = (tuples[i][1] == "true")

    return Admin

def F_1_encrypt(text):
    stripped_text = re.sub('[;=]', '', text)
    text_to_encrypt = T.ext1 + stripped_text + T.ext2
    new_text = CBC_encrypt(text_to_encrypt)

    return new_text

def F_2_decrypt(text):
    d = CBC_decrypt(text)

    s = unPKCS7(d)

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
