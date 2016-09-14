import base64
from Crypto.Cipher import AES

fname = "CP1_7.txt"
orig = open(fname).read()
class Master(object):
    def __init__(self):
        self.aster = ""
M = Master()
M.aster = base64.b64decode(orig)

KEY = "YELLOW SUBMARINE"

IV = 16 * '\x00'           # Initialization vector
mode = AES.MODE_ECB
encryptor = AES.new(KEY, mode, IV=IV)

decryptor = AES.new(KEY, mode, IV=IV)
plain = decryptor.decrypt(M.aster)

print plain
