from hashlib import sha256
from random import randint, SystemRandom
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

class Files(object):
    def __init__(self):
        self.ile = "C:/Users/rices/Coding/CP5_37_server.py "

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
    if len(key) > bsize:
        key = fn(key).digest()
    else:
        key += (b'\x00' * (bsize - len(key)))

    opad = strxor(b'\x5c' * bsize, key)
    ipad = strxor(b'\x36' * bsize, key)

    return fn(opad + fn(ipad + message).digest()).hexdigest()

#######################################################################
# Client's functions
def c1():
    C.N = X.big; C.g = 2; C.k = 3
    C.I = b'foo@bar.gov'; C.psw = b'f1b0n4cc1'

    C.a = cryptrand(C.N)
    C.A = pow(C.g, C.a, C.N)
    return C.I, C.A

def c2(s, B):
    C.s = s; C.B = B
    x = int(sha256(str(C.s) + C.psw).hexdigest(), 16)

    u = int(sha256(str(C.A) + str(C.B)).hexdigest(), 16)

    Sc = pow(C.B - C.k * pow(C.g, x, C.N), C.a + u * x, C.N)

    K = sha256(str(Sc)).digest()

    C.HK = hmac(sha256, str(C.s), K)
    return C.HK

def c2h(s, B):
    C.s = s; C.B = B
    Sc = 0

    K = sha256(str(Sc)).digest()

    C.HK = hmac(sha256, str(C.s), K)
    return C.HK

#######################################################################
# normal and hacked
def norm_proc():
    print "NORMAL:\n"
    print "Client and Server agree on N, g, k, I, and P\n"
    print "Server generates salt integer, hash verifier\n"
    print "Client sends I, A"
    I, A = c1()
    data = "I=" + str(I) + "&A=" + str(A) + "\n"
    sock.sendall(data)
    print data

    print "Server sends salt, B"
    received = sock.recv(1024)
    try:
        s_start = received.find(b's=')
        B_start = received.find(b'&B=')
        s = int(received[s_start + 2: B_start])
        B = int(received[B_start + 3: ])
    except:
        print "Message in incorrect format"
        return 0
    print received

    print "Client and Server calculate u, S, and K"
    print "\nClient sends HMACSHA256(K, salt)"
    HK = c2(s, B)
    data = "HK=" + str(HK) + "\n"
    sock.sendall(data)
    print data

    print "Server sends back OK or not:"
    received = sock.recv(1024)
    try:
        val_start = received.find(b'val=')
        val = received[val_start + 4: ]
    except:
        print "Message in incorrect format"
        return 0
    print received

def hack_proc(Nx):
    print "HACKED (A = N * x):\n"
    print "Client and Server agree on N, g, k, I, and P\n"
    print "Server generates salt integer, hash verifier\n"
    print "Client sends I, A = N * %i" % Nx
    I, A = c1(); A = X.big * Nx
    data = "I=" + str(I) + "&A=" + str(A) + "\n"
    sock.sendall(data)
    print data

    print "Server sends salt, B"
    received = sock.recv(1024)
    try:
        s_start = received.find(b's=')
        B_start = received.find(b'&B=')
        s = int(received[s_start + 2: B_start])
        B = int(received[B_start + 3: ])
    except:
        print "Message in incorrect format"
        return 0
    print received

    print "Client and Server calculate u, S, and K"
    print "\nClient sends HMACSHA256( SHA256(0), salt )"
    HK = c2h(s, B)
    data = "HK=" + str(HK) + "\n"
    sock.sendall(data)
    print data

    print "Server sends back OK or not:"
    received = sock.recv(1024)
    try:
        val_start = received.find(b'val=')
        val = received[val_start + 4: ]
    except:
        print "Message in incorrect format"
        return 0
    print received

#######################################################################
# Main routine (also opens subprocess)
if __name__ == "__main__":
    print ""
    F = Files()
    X = Bignum()
    C = Role()

    subprocess.Popen([sys.executable, F.ile])

    time.sleep(1)
    print "\nParent process running...\n"

    HOST, PORT = "localhost", 9000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try: sock.connect((HOST, PORT))
    except: print "Could not connect to server"

    # norm_proc()
    Nx = randint(0, 5)
    hack_proc(Nx)

    print ""
