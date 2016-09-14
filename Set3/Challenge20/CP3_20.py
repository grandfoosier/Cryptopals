import array
import base64
import sys
from Crypto.Cipher import AES
from random import randint

mode = AES.MODE_ECB

fname = "CP3_20.txt"
lines = [line.rstrip('\n') for line in open(fname)]

class TextFiles(object):
    def __init__(self):
        self.ext = []
T = TextFiles()

def assign_text():
    for i in range (0, len(lines)):
        T.ext.append(base64.b64decode(lines[i]))
assign_text()

lens = []
for i in range(0, len(T.ext)):
    lens.append(len(T.ext[i]))

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

encryptor = AES.new(K.ey, mode)

def freqtest(text):
    score = 0
    arr = array.array('B', text)

    for i in range (len(arr)):
        if   arr[i] in [69,101]:    score += 3.125 # E
        elif arr[i] in [84,116]:    score += 2.366 # T
        elif arr[i] in [65,97]:     score += 2.112 # A
        elif arr[i] in [79,111]:    score += 1.997 # O
        elif arr[i] in [73,105]:    score += 1.899 # I
        elif arr[i] in [78,110]:    score += 1.806 # N
        elif arr[i] in [83,115]:    score += 1.633 # S
        elif arr[i] in [82,114]:    score += 1.566 # R
        elif arr[i] in [72,104]:    score += 1.540 # H
        elif arr[i] in [68,100]:    score += 1.123 # D
        elif arr[i] in [76,108]:    score += 1.034 # L
        elif arr[i] in [85,117]:    score += 0.748 # U
        elif arr[i] in [67,99]:     score += 0.705 # C
        elif arr[i] in [77,109]:    score += 0.679 # M
        elif arr[i] in [70,102]:    score += 0.599 # F
        elif arr[i] in [89,121]:    score += 0.550 # Y
        elif arr[i] in [87,119]:    score += 0.545 # W
        elif arr[i] in [71,103]:    score += 0.527 # G
        elif arr[i] in [80,112]:    score += 0.473 # P
        elif arr[i] in [66,98]:     score += 0.387 # B
        elif arr[i] in [86,118]:    score += 0.288 # V
        elif arr[i] in [75,107]:    score += 0.179 # K
        elif arr[i] in [88,120]:    score += 0.045 # X
        elif arr[i] in [81,113]:    score += 0.029 # Q
        elif arr[i] in [74,106]:    score += 0.027 # J
        elif arr[i] in [90,122]:    score += 0.018 # Z
        elif arr[i] in [32]:        score += 1     # Space
        elif arr[i] in [48,49,50,51,52,53,54,55,56,57]:
            score += 0                             # 0-9
        elif arr[i] not in [33,34,39,44,45,46,47,58,59,63]:
            score = 0; break

    return score

def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)

    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]

    return a3.tostring()

def CTR_transform(text, nonce):
    N = len(text) / 16
    if len(text) % 16 != 0: N += 1

    new_text = ""

    for i in range (0, N):
        stream_text = '\x00'*8 + chr(nonce + i) + '\x00'*7
        KSblock = encryptor.encrypt(stream_text)

        if i < N-1:
            PTblock = text[i*16:(i+1)*16]
        else:
            PTblock = text[i*16:]

        text_to_add = strxor(PTblock, KSblock)

        new_text = new_text + text_to_add

    return new_text

print ""

CTs = []
for i in range (0, len(T.ext)):
    CTs.append(CTR_transform(T.ext[i], 0))

key1 = ""
mixed = []
for i in range (0, min(lens)):
    KSs1 = []
    KSs2 = []

    for j in range (0, 256):
        sys.stdout.write('\b' * 3 + str(j))
        PTs = ""

        for k in range (0, len(CTs)):
            CTbit = CTs[k][i]
            PTbit = strxor(CTbit, chr(j))

            PTs = PTs + PTbit
            score = freqtest(PTs)

        KSs1.append(PTs)
        KSs2.append(score)

    mixed.append(KSs1[KSs2.index(max(KSs2))])
    print "\b\b\b" + mixed[i]
    key1 = key1 + chr(KSs2.index(max(KSs2)))

print ""

unmixed = []
for i in range (0, len(mixed[0])):
    unmixed.append("")
    for j in range (0, len(mixed)):
        unmixed[i] = unmixed[i] + mixed[j][i]
    print unmixed[i]

print ""
