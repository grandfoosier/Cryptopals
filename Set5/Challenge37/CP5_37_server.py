from hashlib import sha256
from random import randint, SystemRandom
import array
import SocketServer
import sys

#######################################################################
# Setup classes
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

class Database(object):
    def __init__(self):
        self.B = {'foo@bar.gov':'f1b0n4cc1', 'e@t.c':'etc'}

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
# Server's functions
def s1(I, A):
    S.N = X.big; S.g = 2; S.k = 3
    S.I = I
    try: S.psw = D.B[I]
    except: self.wfile.write("username not found")

    S.s = cryptrand(S.N, 64)
    x = int(sha256(str(S.s) + S.psw).hexdigest(), 16)
    S.v = pow(S.g, x, S.N)

    S.A = A
    S.b = cryptrand(S.N)
    S.B = S.k * S.v + pow(S.g, S.b, S.N)
    return S.s, S.B

def s2(HK):
    u = int(sha256(str(S.A) + str(S.B)).hexdigest(), 16)

    Ss = pow(S.A * pow(S.v, u, S.N), S.b, S.N)

    K = sha256(str(Ss)).digest()

    S.HK = hmac(sha256, str(S.s), K)

    if S.HK == HK: return "OK"
    else: return "FAIL"

#######################################################################
# Takes file and hashes with HMACSHA1, then checks the given sig
class MyTCPHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        while True:
            jibjab = self.rfile.readline().strip()

            if jibjab == "": break

            try:
                I_start = jibjab.find("I=")
                A_start = jibjab.find("&A=")
                I = jibjab[I_start + 2: A_start]
                A = int(jibjab[A_start + 3: ])
                s, B = s1(I, A)
                data = ("s=" + str(s) + "&B=" + str(B) + "\n")
                self.wfile.write(data)
            except:
                try:
                    HK_start = jibjab.find("HK=")
                    HK = jibjab[HK_start + 3: ]
                    val = s2(HK)
                    data = "val=" + str(val) + "\n"
                    self.wfile.write(data)
                except: self.wfile.write("Message in incorrect format")

#######################################################################
# Sets up the server
def start_server():
    HOST, PORT = "localhost", 9000

    try:
        print "Creating server..."
        server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)
    except:
        print "Could not create server"

    server.allow_reuse_address = True;

    try:
        print "Server starting up..."
        server.serve_forever()
    except:
        print "\r\b\rServer shut down                               "
        print "                                                     "

#######################################################################
# Main routine (still runs if opened in a subprocess)
if __name__ == "__main__":
    X = Bignum()
    S = Role()
    D = Database()

    try: start_server()
    except: print "\rERROR                                "
