import array
from Crypto.Cipher import AES
from random import randint, choice
import base64
import sys
import re

mode = AES.MODE_ECB

class TextFiles(object):
    def __init__(self):
        self.ext = []
T = TextFiles()

def assign_text():
    T.ext.append("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=")
    T.ext.append("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=")
    T.ext.append("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==")
    T.ext.append("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==")
    T.ext.append("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl")
    T.ext.append("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==")
    T.ext.append("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==")
    T.ext.append("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=")
    T.ext.append("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=")
    T.ext.append("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93")
assign_text()

def gen_key():
    key = array.array('B', [])

    for i in range (0, 16):
        key.append(randint(0,255))

    return key.tostring()

class Key(object):
    def __init__(self):
        self.ey = ""
        self.IV = ""
K = Key()
K.ey = gen_key()
K.IV = gen_key()

encryptor = AES.new(K.ey, mode)
decryptor = AES.new(K.ey, mode)

def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)

    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]

    return a3.tostring()

def PKCS7(text):
    raw_N = len(text)
    full_blocks = raw_N / 16
    Nbytes = 16 - (raw_N - (full_blocks * 16))

    text_array = array.array('B', text)

    for i in range (0, Nbytes):
        text_array.append(Nbytes)

    padded_text = text_array.tostring()
    return padded_text

def unPKCS7(text):
    pad = ord(text[-1])
    assert len(text) > pad
    check = 0

    for i in range (0, pad):
        if ord(text[-1 - i]) == pad:
            check += 1

    assert check == pad
    new_text = text[0:pad * -1]
    return new_text

def XOR_ECB(block1, block2):
    combined_text = strxor(block1, block2)

    new_text = encryptor.encrypt(combined_text)

    return new_text

def ECB_XOR(block1, block2):
    decrypted_text = decryptor.decrypt(block2.tostring())

    new_text = strxor(block1, decrypted_text)

    return new_text

def CBC_encrypt(text):
    text_array = array.array('B', PKCS7(text))

    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])
    block_array = array.array('B', XOR_ECB(K.IV, text_array[0:16]))

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

def CBC_decrypt(IV, text):
    text_array = array.array('B', text)
    Nblocks = len(text_array) / 16
    new_text_array = array.array('B', [])

    block_array = array.array('B', ECB_XOR(IV, text_array[0:16]))

    for j in range (len(block_array)):
        new_text_array.append(block_array[j])

    for i in range (1, Nblocks):
        block_array = array.array('B', ECB_XOR(
            text_array[((i - 1) * 16): (i * 16)],
            text_array[(i * 16): ((i + 1) * 16)]))

        for j in range (len(block_array)):
            new_text_array.append(block_array[j])

    new_text = new_text_array.tostring()
    return new_text

def F_1_encrypt():
    plaintext = choice(T.ext)

    ciphertext = CBC_encrypt(plaintext)

    return [K.IV, ciphertext]

def F_2_decrypt(IV, ciphertext):
    possibly_padded_plaintext = CBC_decrypt(IV, ciphertext)

    ppp = possibly_padded_plaintext
    pad = ord(ppp[-1])

    if (pad > 16) or (pad < 1):
        valid_padding = False

    else:
        check = 0

        for i in range (0, pad):
            if ord(ppp[-1 - i]) == pad:
                check += 1

        valid_padding = (check == pad)
    return valid_padding

def find_last_byte(IV, ciphertext):
    CT = ciphertext

    for i in range (2, 258):
        CT0 = (CT[:-17] +
               chr(ord(CT[-17]) ^ 1 ^ i%256) +
               CT[-16:])
        valid = F_2_decrypt(IV, CT0)

        if valid: break

    return i%256

def find_byte_n(IV, ciphertext, known):
    CTa = array.array('B', ciphertext)
    N = len(known)

    for i in range(1, N+1):
        CTa[-i - 16] = (CTa[-i - 16] ^ ord(known[-i]) ^ (N+1))

    CT = CTa.tostring()

    for i in range (0, 256):
        CT0 = (CT[:-1*(N+1) - 16] +
               chr(ord(CT[-1*(N+1) - 16]) ^ (N+1) ^ i) +
               CT[-1*(N+1) - 15:])
        valid = F_2_decrypt(IV, CT0)

        if valid: break

    return i

print ""
packet = F_1_encrypt()
print ""

N = len(packet[1]) / 16
IVCT = packet[0] + packet[1]
IV_0 = '\x00' * 16

for i in range(0, N):
    last_byte = find_last_byte(IV_0, IVCT[:len(IVCT) - i*16])

    if i == 0: known = chr(last_byte) * last_byte
    else: known = chr(last_byte) + known

    sys.stdout.write('\b' * len(known) + known)

    while (len(known) % 16) != 0:
        known = (chr(find_byte_n(
                        IV_0,
                        IVCT[:len(IVCT) - i*16],
                        known[:len(known) - i*16]))
                + known)

        sys.stdout.write('\b' * len(known) + known)

print "\n"

pad = ord(known[-1])
Tin64 = known[:-pad]
secret_message = base64.b64decode(Tin64)

print secret_message
print ""
