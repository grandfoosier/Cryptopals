import array
import base64
from Crypto.Cipher import AES

mode = AES.MODE_ECB

class TextFiles(object):
    def __init__(self):
        self.ext = ""
T = TextFiles()
T.ext = base64.b64decode(
         "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/"+
         "2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

class Key(object):
    def __init__(self):
        self.ey = ""
K = Key()
K.ey = "YELLOW SUBMARINE"

encryptor = AES.new(K.ey, mode)

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

    for i in range (0, N):
        stream_text = '\x00'*8 + chr(i) + '\x00'*7
        KSblock = encryptor.encrypt(stream_text)

        if i < N-1:
            PTblock = text[i*16:(i+1)*16]
        else:
            PTblock = text[i*16:]

        text_to_add = strxor(PTblock, KSblock)

        new_text = new_text + text_to_add

    return new_text

print ""
new_text = CTR_transform(T.ext)

print new_text, "\n"

text_3 = CTR_transform(new_text)

print text_3, "\n"
