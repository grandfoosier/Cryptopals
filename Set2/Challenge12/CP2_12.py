import array
from Crypto.Cipher import AES
from random import randint
import base64
import binascii
import sys

mode = AES.MODE_ECB
zeroskey = 16 * '\x00'
IV = 16 * '\x00'
encryptor = AES.new(zeroskey, mode)
decryptor = AES.new(zeroskey, mode)

fname1 = "Ex2_11.txt"
class TextFiles(object):
    def __init__(self):
        self.ext1 = ""
T = TextFiles()
T.ext1 = open(fname1).read()

def gen_key():
    key = array.array('B', [])
    for i in range (0, 16):
        key.append(randint(0,255))
    return key.tostring()

class Key(object):
    def __init__(self):
        self.ey = ""
        self.icker = ""
K = Key()
K.ey = gen_key()

class CodeList(object):
    def __init__(self):
        self.locks = []
B = CodeList()

addon = """
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
	aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
	dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
	YnkK"""
K.icker = base64.b64decode(addon.strip('\n\t'))

def PKCS7(text, pad):
    text_array = array.array('B', text)
    N = len(text_array)
    for i in range (0, pad):
        text_array.append(pad)
    padded_text = text_array.tostring()
    return padded_text

def ECB_encrypt_plus(text):
    encryptor = AES.new(K.ey, mode)
    text_plus = text + K.icker

    raw_N = len(text_plus)
    full_blocks = raw_N / 16
    Nbytes = 16 - (raw_N - (full_blocks * 16))
    padded_text = PKCS7(text_plus, Nbytes)

    new_text = encryptor.encrypt(padded_text)
    return new_text

def detect_block_length():
    text = 1 * '\x65'
    new_text = ECB_encrypt_plus(text)
    comp_len = len(new_text)
    for i in range(1, 21):
        text = i * '\x65'
        new_text = ECB_encrypt_plus(text)
        iter_len = len(new_text)
        if iter_len > comp_len:
            block_length = iter_len - comp_len
            break
    return block_length

def detect_ECB(text):
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
    return (maxdupes == 16)

def create_block_dict(text, SM, block_length, N):
    B.locks = []
    for i in range(0, 256):
        new_text = text + SM + chr(i)
        returned_text = ECB_encrypt_plus(new_text)
        B.locks.append(returned_text[N:
            (N + 1) * block_length])

def last_byte_is(text, SM, block_length, N):
    create_block_dict(text, SM, block_length, N)
    last_byte_block = ECB_encrypt_plus(text)[N:
        (N + 1) * block_length]
    return chr(B.locks.index(last_byte_block))

def find_lenK():
    text1 = ""
    len0 = len(ECB_encrypt_plus(text1))
    for i in range (1, 15):
        text1 = '\x00' * i
        text = ECB_encrypt_plus(text1)
        comp_len = len(text)
        if comp_len > len0:
            lenK = (len(text) - i - 16)
            break

    return lenK

block_length = detect_block_length()
print block_length
print detect_ECB(T.ext1)

secret_message = ""
print ""

lenK = find_lenK()

for l in range (0, lenK):
    # pct = (l * 100 / len(K.icker))
    # sys.stdout.write('\b\b\b\b' + str(pct) + "%")
    N = (l / block_length)
    text = (block_length - (l % block_length) - 1) * '\x41'
    secret_message = secret_message + last_byte_is(
        text, secret_message, block_length, N)
    sys.stdout.write(secret_message[-1])

# print "\b\b\b\b" + secret_message
print ""
