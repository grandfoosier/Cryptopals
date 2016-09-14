import binascii
print "\n"

str1ng = raw_input(". ")
unhex1 = binascii.unhexlify(str1ng)

str2ng = raw_input(". ")
unhex2 = binascii.unhexlify(str2ng)

def strxor(s1, s2) :
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

unhex3 = strxor(unhex1, unhex2)
str3ng = binascii.hexlify(unhex3)
print "  " + str3ng + "\n"
