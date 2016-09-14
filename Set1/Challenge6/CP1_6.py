import binascii
import base64
import array

fname = "CP1_6.txt"
orig = open(fname).read()
class Master(object):
    def __init__(self):
        self.aster = ""
M = Master()
M.aster = base64.b64decode(orig)

class Lst(object):
    def __init__(self):
        self.ist1 = []
        self.ist2 = []
L = Lst()

def d2b(x):
    return bin(x)[2:]

def strxor(a1, a2):
    a3 = array.array('B', a1)
    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]
    return a3.tostring()

def smelltest(text):
    Caps = 0; Lows = 0; Spcs = 0
    arr = array.array('B', text)
    for i in range (len(arr)):
        if arr[i] == 32: Spcs += 1
        elif arr[i] in range (64, 90): Caps += 1
        elif arr[i] in range (97, 122): Lows += 1
    Tot = Caps + Lows + Spcs
    Pct = (Tot * 1.0) / len(arr)
    L.ist.append(Tot)

def freqtest(text):
    score = 0
    arr = array.array('B', text)
    for i in range (len(arr)):
        if   arr[i] in [69,101]: score += 3.125 # E
        elif arr[i] in [84,116]: score += 2.366 # T
        elif arr[i] in [65,97]:  score += 2.112 # A
        elif arr[i] in [79,111]: score += 1.997 # O
        elif arr[i] in [73,105]: score += 1.899 # I
        elif arr[i] in [78,110]: score += 1.806 # N
        elif arr[i] in [83,115]: score += 1.633 # S
        elif arr[i] in [82,114]: score += 1.566 # R
        elif arr[i] in [72,104]: score += 1.540 # H
        elif arr[i] in [68,100]: score += 1.123 # D
        elif arr[i] in [76,108]: score += 1.034 # L
        elif arr[i] in [85,117]: score += 0.748 # U
        elif arr[i] in [67,99]:  score += 0.705 # C
        elif arr[i] in [77,109]: score += 0.679 # M
        elif arr[i] in [70,102]: score += 0.599 # F
        elif arr[i] in [89,121]: score += 0.550 # Y
        elif arr[i] in [87,119]: score += 0.545 # W
        elif arr[i] in [71,103]: score += 0.527 # G
        elif arr[i] in [80,112]: score += 0.473 # P
        elif arr[i] in [66,98]:  score += 0.387 # B
        elif arr[i] in [86,118]: score += 0.288 # V
        elif arr[i] in [75,107]: score += 0.179 # K
        elif arr[i] in [88,120]: score += 0.045 # X
        elif arr[i] in [81,113]: score += 0.029 # Q
        elif arr[i] in [74,106]: score += 0.027 # J
        elif arr[i] in [90,122]: score += 0.018 # Z
        elif arr[i] == 32: score += 1.000 # Space
        elif (arr[i] < 32) or (arr[i] > 126): score -= 1
    L.ist.append(score)

def find_single_key(text):
    array1 = array.array('B', text)
    L.ist = []
    for j in range (0, 256):
        array2 = array.array('B', [j] * len(array1))
        text = strxor(array1, array2)
        freqtest(text)
    best = L.ist.index(max(L.ist))
    return best

def hamming(s1, s2):
    assert len(s1) == len(s2)

    array1 = array.array('B', s1)
    array2 = array.array('B', s2)

    binstr1 = ""
    binstr2 = ""

    for i in range (len(s1)):
        bin1 = d2b(array1[i])
        while len(bin1) < 8: bin1 = "0" + bin1
        bin2 = d2b(array2[i])
        while len(bin2) < 8: bin2 = "0" + bin2
        binstr1 += bin1
        binstr2 += bin2

    hamm = 0
    for chr1, chr2 in zip(binstr1, binstr2):
        if chr1 != chr2: hamm += 1
    return hamm

def hamm_per_key(ks):
    s1 = M.aster[0:ks]
    s2 = M.aster[ks:ks*2]
    s3 = M.aster[ks*2:ks*3]
    s4 = M.aster[ks*3:ks*4]
    s5 = M.aster[ks*4:ks*5]
    s6 = M.aster[ks*5:ks*6]
    h1 = hamming(s1,s2)
    h2 = hamming(s2,s3)
    h3 = hamming(s3,s4)
    h4 = hamming(s4,s5)
    h5 = hamming(s5,s6)
    avgh = (h1 + h2 + h3+ h4 + h5) / 5.0 / ks
    return avgh

def decrypt(s1, s2, KS):
    array1 = array.array('B', s1)
    N1 = len(array1); M1 = N1 / KS + 1
    encrypt1 = array.array('B', s2 * M1)
    new_text1 = strxor(array1, encrypt1)
    return new_text1

hamms = [10,10]
for ks in range (2, 40):
    hamms.append(hamm_per_key(ks))

for i in range (0,5):
    best = hamms.index(min(hamms))
    print "%i: %r" % (best, hamms[best])
    hamms[best] = 10
KS = int(raw_input(". "))
print KS

blocks = []
for block in range (0, KS):
    blocks.append("")

for n in range(0, len(M.aster)):
    blocks[n % KS] = blocks[n % KS] + M.aster[n]

KEY = ""
for i in range (len(blocks)):
    KEY = KEY + chr(find_single_key(blocks[i]))
    print "Key:", KEY, "\n"
pause = raw_input()

print decrypt(M.aster, KEY, KS)
