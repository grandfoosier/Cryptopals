import binascii
import array

fname = "CP1_4.txt"
all_file = open("CP1_4_all.txt", 'w')

lines = [line.rstrip('\n') for line in open(fname)]

line_stats = []
line_pcts = []

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
    L.ist2.append(Pct)

def freqtest(tex, Nl, j):
    score = 0
    arr = array.array('B', tex)
    for i in range (len(arr)):
        if   arr[i] in [69,101]:              score += 3.125 # E
        elif arr[i] in [84,116]:              score += 2.366 # T
        elif arr[i] in [65,97]:               score += 2.112 # A
        elif arr[i] in [79,111]:              score += 1.997 # O
        elif arr[i] in [73,105]:              score += 1.899 # I
        elif arr[i] in [78,110]:              score += 1.806 # N
        elif arr[i] in [83,115]:              score += 1.633 # S
        elif arr[i] == 82 or arr[i] == 114:   score += 1.566 # R
        elif arr[i] == 72 or arr[i] == 104:   score += 1.540 # H
        elif arr[i] == 68 or arr[i] == 100:   score += 1.123 # D
        elif arr[i] in [76,108]:              score += 1.034 # L
        elif arr[i] in [85,117]:              score += 0.748 # U
        elif arr[i] in [67,99]:               score += 0.705 # C
        elif arr[i] == 77 or arr[i] == 109:   score += 0.679 # M
        elif arr[i] in [70,102]:              score += 0.599 # F
        elif arr[i] in [89,121]:              score += 0.550 # Y
        elif arr[i] == 87 or arr[i] == 119:   score += 0.545 # W
        elif arr[i] == 71 or arr[i] == 103:   score += 0.527 # G
        elif arr[i] in [80,112]:              score += 0.473 # P
        elif arr[i] == 66 or arr[i] == 98:    score += 0.387 # B
        elif arr[i] == 86 or arr[i] == 118:   score += 0.288 # V
        elif arr[i] == 75 or arr[i] == 107:   score += 0.179 # K
        elif arr[i] in [88,120]:              score += 0.045 # X
        elif arr[i] == 81 or arr[i] == 113:   score += 0.029 # Q
        elif arr[i] == 74 or arr[i] == 106:   score += 0.027 # J
        elif arr[i] in [90,122]:              score += 0.018 # Z
        elif arr[i] == 32: score += 1 # Space
        elif (arr[i] < 32) or (arr[i] > 126): score -= 1
    if score > 0:
        all_file.write("%i, %i, %s\n" % (Nl, j, tex))
    L.ist1.append(tex)
    L.ist2.append(score)

print ""
for Nl in range (len(lines)):
    print "line", Nl
    unhex1 = binascii.unhexlify(lines[Nl])
    array1 = array.array('B', unhex1)
    N = len(array1)

    L.ist1 = []; L.ist2 = []
    for j in range (0, 256):
        array2 = array.array('B', [j] * N)
        unhex3 = strxor(array1, array2, N)
        smelltest(unhex3)
        # freqtest(unhex3, Nl, j)

    best = L.ist2.index(max(L.ist2))
    line_stats.append([Nl, lines[Nl], best, L.ist1[best]])
    line_pcts.append(max(L.ist2))

best = line_pcts.index(max(line_pcts))
print ""
print "Line", line_stats[best][0]
print "Key:", line_stats[best][2], "-", chr(line_stats[best][2])
print ""
print line_stats[best][3]
print ""
