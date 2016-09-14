import base64
from Crypto.Cipher import AES
import array

fname = "CP2_10.txt"
orig = open(fname).read()
class Master(object):
    def __init__(self):
        self.aster = ""
M = Master()
M.aster = base64.b64decode(orig)

KEY = "YELLOW SUBMARINE"
IV = 16 * '\x00'

mode = AES.MODE_ECB
encryptor = AES.new(KEY, mode)
decryptor = AES.new(KEY, mode)

def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)
    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]
    return a3.tostring()

def PKCS7(text, pad):
    text_array = array.array('B', text)
    N = len(text_array)
    for i in range (0, pad):
        text_array.append(pad)
    padded_text = text_array.tostring()
    return padded_text

def XOR_ECB(block1, block2):
    combined_text = strxor(block1, block2)
    new_text = encryptor.encrypt(combined_text)
    return new_text

def ECB_XOR(block1, block2):
    decrypted_text = decryptor.decrypt(block2.tostring())
    new_text = strxor(block1, decrypted_text)
    return new_text

def CBC_encrypt(text, IV):
    raw_N = len(text)
    full_blocks = raw_N / 16
    Nbytes = 16 - (raw_N - (full_blocks * 16))
    text_array = array.array('B', PKCS7(text, Nbytes))

    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])

    block_array = array.array('B', XOR_ECB(IV, text_array[0:16]))
    for i in range (0, 16):
        new_text_array.append(block_array[i])

    for i in range (1, Nblocks):
        block_array = array.array('B', XOR_ECB(
            new_text_array[((i-1)*16):(i*16)],
            text_array[(i*16):((i+1)*16)]))
        for j in range (0, 16):
            new_text_array.append(block_array[j])

    new_text = new_text_array.tostring()
    return new_text

def CBC_decrypt(text, IV):
    text_array = array.array('B', text)
    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])

    for i in range (0, Nblocks - 1):
        j = Nblocks - i
        block_array = array.array('B', ECB_XOR(
            text_array[((j - 2) * 16): ((j - 1) * 16)],
            text_array[((j - 1) * 16): (j * 16)]))
        for k in range (0, 16):
            new_text_array.insert(0, block_array[15 - k])

    block_array = array.array('B', ECB_XOR(IV, text_array[0:16]))
    for j in range (0, 16):
        new_text_array.insert(0, block_array[15 - j])

    new_text = new_text_array.tostring()
    return new_text

decrypted = CBC_decrypt(M.aster, IV)
encrypted = CBC_encrypt(decrypted, IV)
print CBC_decrypt(encrypted, IV)
