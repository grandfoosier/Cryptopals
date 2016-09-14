import binascii
import array

print ""
string1 = raw_input(". ")
unhex1 = binascii.unhexlify(string1)
array1 = array.array('B', unhex1)
N = len(array1)

class Lst(object):
    def __init__(self):
        self.ist1 = []
        self.ist2 = []
L = Lst()

def strxor(a1, a2, N):
    a3 = array.array('B', a1)
    for i in range(N):
        a3[i] = a1[i] ^ a2[i]
    return a3.tostring()

def smelltest(tex):
    Caps = 0; Lows = 0; Spcs = 0
    arr = array.array('B', tex)
    for i in range (len(arr)):
        if arr[i] == 32: Spcs += 1
        elif arr[i] in range (64, 90): Caps += 1
        elif arr[i] in range (97, 122): Lows += 1
    Tot = Caps + Lows + Spcs
    Pct = (Tot * 1.0) / len(arr)
    L.ist1.append(tex)
    L.ist2.append(Tot)

for j in range (0, 256):
    array2 = array.array('B', [j] * N)
    unhex3 = strxor(array1, array2, N)
    print unhex3
    smelltest(unhex3)

for i in range (0,5):
    best = L.ist2.index(max(L.ist2))
    print ""
    print "Key:", best, "-", chr(best), ";", L.ist2[best]
    print ""
    print L.ist1[best]
    print ""
    L.ist2[best] = 0
