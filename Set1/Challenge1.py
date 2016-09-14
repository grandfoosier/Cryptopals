import sys
import binascii
import base64

str1ng = sys.argv[1]
str2ng = binascii.unhexlify(str1ng)
str3ng = base64.b64encode(str2ng)
print "\n" + str3ng + "\n"
