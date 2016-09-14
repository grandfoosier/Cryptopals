import array
import base64
import sys
from Crypto.Cipher import AES
from random import randint

mode = AES.MODE_ECB

class TextFiles(object):
    def __init__(self):
        self.ext = []
T = TextFiles()

def assign_text():
    T.ext.append("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==")
    T.ext.append("Q29taW5nIHdpdGggdml2aWQgZmFjZXM=")
    T.ext.append("RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==")
    T.ext.append("RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=")
    T.ext.append("SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk")
    T.ext.append("T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==")
    T.ext.append("T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=")
    T.ext.append("UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==")
    T.ext.append("QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=")
    T.ext.append("T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl")
    T.ext.append("VG8gcGxlYXNlIGEgY29tcGFuaW9u")
    T.ext.append("QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==")
    T.ext.append("QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=")
    T.ext.append("QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==")
    T.ext.append("QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=")
    T.ext.append("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=")
    T.ext.append("VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==")
    T.ext.append("SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==")
    T.ext.append("SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==")
    T.ext.append("VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==")
    T.ext.append("V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==")
    T.ext.append("V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==")
    T.ext.append("U2hlIHJvZGUgdG8gaGFycmllcnM/")
    T.ext.append("VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=")
    T.ext.append("QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=")
    T.ext.append("VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=")
    T.ext.append("V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=")
    T.ext.append("SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==")
    T.ext.append("U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==")
    T.ext.append("U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=")
    T.ext.append("VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==")
    T.ext.append("QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu")
    T.ext.append("SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=")
    T.ext.append("VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs")
    T.ext.append("WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=")
    T.ext.append("SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0")
    T.ext.append("SW4gdGhlIGNhc3VhbCBjb21lZHk7")
    T.ext.append("SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=")
    T.ext.append("VHJhbnNmb3JtZWQgdXR0ZXJseTo=")
    T.ext.append("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=")
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

encryptor = AES.new(K.ey, mode)

def freqtest(text):
    score = 0
    arr = array.array('B', text)

    for i in range (len(arr)):
        if   arr[i] in [69,101]:              score += 3.125 # E
        elif arr[i] in [84,116]:              score += 2.366 # T
        elif arr[i] in [65,97]:               score += 2.112 # A
        elif arr[i] in [79,111]:              score += 1.997 # O
        elif arr[i] in [73,105]:              score += 1.899 # I
        elif arr[i] in [78,110]:              score += 1.806 # N
        elif arr[i] in [83,115]:              score += 1.633 # S
        elif arr[i] == 82 or arr[i] == 114:   score += 1.566 # R
        elif arr[i] == 72 or arr[i] == 104:   score += 1.540 # H
        elif arr[i] == 68 or arr[i] == 100:   score += 1.123 # D
        elif arr[i] in [76,108]:              score += 1.034 # L
        elif arr[i] in [85,117]:              score += 0.748 # U
        elif arr[i] in [67,99]:               score += 0.705 # C
        elif arr[i] == 77 or arr[i] == 109:   score += 0.679 # M
        elif arr[i] in [70,102]:              score += 0.599 # F
        elif arr[i] in [89,121]:              score += 0.550 # Y
        elif arr[i] == 87 or arr[i] == 119:   score += 0.545 # W
        elif arr[i] == 71 or arr[i] == 103:   score += 0.527 # G
        elif arr[i] in [80,112]:              score += 0.473 # P
        elif arr[i] == 66 or arr[i] == 98:    score += 0.387 # B
        elif arr[i] == 86 or arr[i] == 118:   score += 0.288 # V
        elif arr[i] == 75 or arr[i] == 107:   score += 0.179 # K
        elif arr[i] in [88,120]:              score += 0.045 # X
        elif arr[i] == 81 or arr[i] == 113:   score += 0.029 # Q
        elif arr[i] == 74 or arr[i] == 106:   score += 0.027 # J
        elif arr[i] in [90,122]:              score += 0.018 # Z
        elif arr[i] == 32: score += 1 # Space
        elif (arr[i] < 32) or (arr[i] > 126): score -= 1

    return score

def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)

    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]

    return a3.tostring()

def CTR_transform(text, nonce):
    N = len(text) / 16
    if len(text) % 16 != 0: N += 1

    new_text = ""

    for i in range (nonce, nonce + N):
        stream_text = '\x00'*8 + chr(i) + '\x00'*7
        KSblock = encryptor.encrypt(stream_text)

        if i < N-1:
            PTblock = text[i*16:(i+1)*16]
        else:
            PTblock = text[i*16:]

        text_to_add = strxor(PTblock, KSblock)

        new_text = new_text + text_to_add

    return new_text

print ""
print CTR_transform("\x00" * 16, 0)

CTs = []
for i in range (0, len(T.ext)):
    CTs.append(CTR_transform(base64.b64decode(T.ext[i]), 0))

key = ""
for i in range (0, 16):
    KSs1 = []
    KSs2 = []

    for j in range (0, 256):
        sys.stdout.write('\b\b\b' + str(j))

        PTs = ""

        for k in range (0, len(CTs)):
            CTbit = CTs[k][i]
            PTbit = strxor(CTbit, chr(j))

            PTs = PTs + PTbit
            score = freqtest(PTs)

        KSs1.append(PTs)
        KSs2.append(score)

    print "\b\b\b" + KSs1[KSs2.index(max(KSs2))]
    key = key + chr(KSs2.index(max(KSs2)))

print key
