import array
from Crypto.Cipher import AES
from random import randint

fname = "CP2_11.txt"
class Master(object):
    def __init__(self):
        self.aster = ""
M = Master()
M.aster = open(fname).read()

mode = AES.MODE_ECB
zeroskey = 16 * '\x00'
IV = 16 * '\x00'
encryptor = AES.new(zeroskey, mode)
decryptor = AES.new(zeroskey, mode)

def gen_key():
    key = array.array('B', [])
    for i in range (0, 16):
        key.append(randint(0,255))
    return key.tostring()

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

def XOR_ECB(block1, block2, KEY):
    encryptor = AES.new(KEY, mode)

    combined_text = strxor(block1, block2)
    new_text = encryptor.encrypt(combined_text)
    return new_text

def ECB_XOR(block1, block2):
    decrypted_text = decryptor.decrypt(block2.tostring())
    new_text = strxor(block1, decrypted_text)
    return new_text

def ECB_encrypt(text, KEY):
    print " ECB"
    encryptor = AES.new(KEY, mode)

    raw_N = len(text)
    full_blocks = raw_N / 16
    Nbytes = 16 - (raw_N - (full_blocks * 16))
    padded_text = PKCS7(text, Nbytes)

    new_text = encryptor.encrypt(padded_text)
    return new_text

def ECB_decrypt(text):
    new_text = decryptor.decrypt(text)
    return new_text

def CBC_encrypt(text, IV, KEY):
    print " CBC"
    raw_N = len(text)
    full_blocks = raw_N / 16
    Nbytes = 16 - (raw_N - (full_blocks * 16))
    text_array = array.array('B', PKCS7(text, Nbytes))

    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])

    block_array = array.array('B', XOR_ECB(IV, text_array[0:16], KEY))
    for i in range (0, 16):
        new_text_array.append(block_array[i])

    for i in range (1, Nblocks):
        block_array = array.array('B', XOR_ECB(
            new_text_array[((i-1)*16):(i*16)],
            text_array[(i*16):((i+1)*16)], KEY))
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

def encryption_oracle(text):
    text_array = array.array('B', text)

    pre = randint(5, 10)
    post = randint(5, 10)

    for i in range (0, pre):
        text_array.insert(0, pre)
    for i in range (0, post):
        text_array.append(post)

    ECB_or_CBC = randint(1, 2)
    KEY = gen_key()
    if ECB_or_CBC == 1:
        encrypted_text = ECB_encrypt(text, KEY)
    else:
        IV = gen_key()
        encrypted_text = CBC_encrypt(text, IV, KEY)
    return encrypted_text

def detect_16byte_repeat(text):
    arr1 = array.array('B', text)
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

code = encryption_oracle(M.aster)
maxdupes = detect_16byte_repeat(code)
print "", maxdupes
if maxdupes == 16: print " ECB"
else: print " CBC"
