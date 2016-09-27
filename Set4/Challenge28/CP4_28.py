from hashlib import sha1
import base64
import array
from random import randint

############################################################
# set text
class TextFiles(object):
    def __init__(self):
        self.ext = (
            "How many boards would the Mongols hoard "
          + "if the Mongol hordes got bored?")
T = TextFiles()

############################################################
# generate random key
def gen_key():
    key = array.array('B', [])

    for i in range (0, 16):
        key.append(randint(0,255))

    return key.tostring()
class Key(object):
    def __init__(self):
        self.ey = gen_key()
K = Key()

############################################################
# generate SHA1 MAC with secret key
def SHA1wKey(text):
    MAC = base64.b64encode(sha1(K.ey + text).digest())
    return MAC

############################################################
# test MAC response to small changes in PT
def nudge():
    x = 0
    MAC = SHA1wKey(T.ext)

    for i in range(0, len(T.ext)):
        text = (T.ext[:i] + chr((ord(T.ext[i]) + 1) % 256) +
                T.ext[i + 1:])
        MACi = SHA1wKey(text)

        for j in range (0, len(MAC)):
            if MAC[j] != MACi[j]: x += 1

    v = x * 1.0 / len(MAC) / len(T.ext) * 100
    print str(v)[0:5] + "% volatility"

############################################################
# try to recreate a MAC
def collide():
    MAC = SHA1wKey(T.ext)

    for i in range(0, 100000):
        key = gen_key()
        MACi = base64.b64encode(sha1(key + T.ext).digest())

        if MACi == MAC:
            print "Woah that shouldn't have happened!!"
            return 0

    print "Safe!"
    return 1

print ""
nudge()
print ""
collide()
print "\n"
