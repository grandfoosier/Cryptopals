from hashlib import sha256
from random import randint, SystemRandom, choice
import array
import socket
import subprocess
import sys
import time
import web

#######################################################################
# Setup
def cryptrand(N, n = 1024):
    return SystemRandom().getrandbits(n) % N

class Bignum(object):
    def __init__(self):
        self.big = (
            '00c037c37588b4329887e61c2da3324b1ba4b81a' +
            '63f9748fed2d8a410c2fc21b1232f0d3bfa02427' +
            '6cfd88448197aae486a63bfca7b8bf7754dfb327' +
            'c7201f6fd17fd7fd74158bd31ce772c9f5f8ab58' +
            '4548a99a759b5a2c0532162b7b6218e8f142bce2' +
            'c30d7784689a483e095e701618437913a8c39c3d' +
            'd0d4ca3c500b885fe3')
        self.big = int(self.big, 16)

class Role(object):
    def __init__(self):
        pass

#######################################################################
# HMAC code
def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)

    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]

    return a3.tostring()

def hmac(fn, key, message):
    bsize = fn().block_size

    if len(key) > bsize: key = fn(key).digest()
    else: key += (b'\x00' * (bsize - len(key)))

    opad = strxor(b'\x5c' * bsize, key)
    ipad = strxor(b'\x36' * bsize, key)

    return fn(opad + fn(ipad + message).digest()).hexdigest()

#######################################################################
# Client's functions
def c1():
    C.N = X.big; C.g = 2
    C.I = b'foo@bar.gov'; C.psw = "hamburger"
    C.a = cryptrand(C.N)
    C.A = pow(C.g, C.a, C.N)

    return C.I, C.A

def c2(s, B, u):
    C.s = s; C.B = B; C.u = u

    x = int(sha256(str(C.s) + C.psw).hexdigest(), 16)
    Sc = pow(C.B, C.a + C.u * x, C.N)
    K = sha256(str(Sc)).digest()
    C.HK = hmac(sha256, str(C.s), K)

    return C.HK

#######################################################################
# Man-in-the-Middle's functions
def m1(I, A):
    M.N = X.big; M.g = 2 # Would we know N and g?
    M.I = I; M.A = A

    M.s = cryptrand(M.N, 64)
    M.b = cryptrand(M.N)
    M.B = pow(M.g, M.b, M.N)
    M.u = cryptrand(M.N, 128)

    return M.s, M.B, M.u

def m2(HK):
    fname = "NGSL6plus.txt"; ln = 1
    for line in open(fname):
        psw = line.rstrip('\n')
        print "\r" + str(ln) + "   " + psw + "                ",

        x = int(sha256(str(M.s) + psw).hexdigest(), 16)
        v = pow(M.g, x, M.N)
        Sm = pow(M.A * pow(v, M.u, M.N), M.b, M.N)
        K = sha256(str(Sm)).digest()
        HKm = hmac(sha256, str(M.s), K)

        if HKm == HK:
            M.psw = psw
            print ""
            return M.psw

        ln += 1

    print "\rPassword not found"
    return 0

#######################################################################
# normal and hacked
def norm_proc():
    print "NORMAL:\n"
    print "Client and Server agree on N, g, I, and P\n"
    print "Server generates salt integer, hash verifier\n"
    print "Client sends I, A"
    I, A = c1()
    data = "I=" + str(I) + "&A=" + str(A) + "\n"
    sock.sendall(data)
    print data

    print "Server sends salt, B, u = 128 bit random"
    received = sock.recv(2048)
    print received
    try:
        s_start = received.find(b's=')
        B_start = received.find(b'&B=')
        u_start = received.find(b'&u=')
        s = int(received[s_start + 2: B_start])
        B = int(received[B_start + 3: u_start])
        u = int(received[u_start + 3: ])
    except:
        print "Server message in incorrect format"
        return 0


    print "Client and Server calculate S and K"
    print "\nClient sends HMACSHA256(K, salt)"
    HK = c2(s, B, u)
    data = "HK=" + str(HK) + "\n"
    sock.sendall(data)
    print data

    print "Server sends back OK or not:"
    received = sock.recv(1024)
    print received
    try:
        val_start = received.find(b'val=')
        val = received[val_start + 4: ]
    except:
        print "Message in incorrect format"
        return 0

def hack_proc():
    print "NORMAL:\n"
    print "Client and Server agree on N and g"
    print "Man-in-the-Middle intercepts?\n"
    print "Client sends I, A"
    I, A = c1()
    data = "I=" + str(I) + "&A=" + str(A) + "\n"
    print data

    print "MITM intercepts"
    print "MITM sends arbitrary salt, B, u = 128 bit random"
    s, B, u = m1(I, A)
    data = ("s=" + str(s) + "&B=" + str(B) +
            "&u=" + str(u) + "\n")
    print data

    print "Client calculates S and K"
    print "\nClient sends HMACSHA256(K, salt)"
    HK = c2(s, B, u)
    data = "HK=" + str(HK) + "\n"
    print data

    print "MITM intercepts, performs dictionary attack"
    psw = m2(HK)

#######################################################################
# Main routine (also opens subprocess)
if __name__ == "__main__":
    print ""
    X = Bignum()
    C = Role(); M = Role()

    subprocess.Popen([sys.executable,
        "C:/Users/rices/Coding/CP5_38_server.py "])

    time.sleep(1)
    print "\nParent process running...\n"

    HOST, PORT = "localhost", 9000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try: sock.connect((HOST, PORT))
    except: print "Could not connect to server"

    # norm_proc()
    hack_proc()

    print ""
