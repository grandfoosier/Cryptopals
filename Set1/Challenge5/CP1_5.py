import binascii
import array

fname = "CP1_5.txt"

def strxor(a1, a2):
    a3 = array.array('B', a1)
    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]
    return a3.tostring()

print ""
string1 = open(fname).read()

array1 = array.array('B', string1)
N1 = len(array1); M1 = N1 / 3 + 1
encrypt1 = array.array('B', "ICE" * M1)
new_text1 = strxor(array1, encrypt1)
hex1 = binascii.hexlify(new_text1)
print hex1
