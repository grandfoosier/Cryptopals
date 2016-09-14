import binascii
import array

fname = "CP1_8.txt"
lines = [line.rstrip('\n') for line in open(fname)]

def detect_16byte_repeat(s):
    arr1 = array.array('B', s)
    maxdupes = 0
    N = len(arr1) / 16
    for i in range (0, N-2):
        for j in range (i+1, N-1):
            dupes = 0
            for k in range (0, 16):
                if arr1[i*16 + k] != arr1[j*16 + k]:
                    break
                dupes += 1
            if dupes > maxdupes: maxdupes = dupes
    return maxdupes

maxes = []
for i in range (0, len(lines)):
    maxes.append(detect_16byte_repeat(lines[i]))

best = maxes.index(max(maxes))
print "\nLine %i contains repetition of %i bytes\n" % (
    best, maxes[best])
