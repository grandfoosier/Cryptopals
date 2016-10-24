from hashlib import sha1
from random import randint
import array
import time
import SocketServer
import sys

#######################################################################
# Setup classes
class Delay(object):
    def __init__(self):
        self.lay = 0.05
def gen_key():
    key = ""
    l = randint(3, 13)

    for i in range (0, l):
        key = key + chr(randint(97, 122))

    return key
class Key(object):
    def __init__(self):
        self.ey = gen_key()
        self.YS = "YELLOW SUBMARINE"

#######################################################################
# String XOR function for HMAC
def strxor(a1, a2):
    a1 = array.array('B', a1)
    a2 = array.array('B', a2)
    a3 = array.array('B', a1)

    for i in range(len(a1)):
        a3[i] = a1[i] ^ a2[i]

    return a3.tostring()

#######################################################################
# HMAC-SHA1 code
def hmacsha1(key, message):
    if len(key) > 64:
        key = hash(key)
    else:
        key += (b'\x00' * (64 - len(key)))

    opad = strxor(b'\x5c' * 64, key)
    ipad = strxor(b'\x36' * 64, key)

    return sha1(opad + sha1(ipad + message).digest()).digest()

#######################################################################
# Byte-by-byte comparison with delay
def insecure_compare(a, b):
    if len(a) != len(b): return False

    for i in range(len(a)):
        if a[i] != b[i]: return False
        time.sleep(D.lay)

    return True

#######################################################################
# Takes file and hashes with HMACSHA1, then checks the given sig
class MyTCPHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        while True:
            jibjab = self.rfile.readline().strip()

            if jibjab == "": break

            msg_start = jibjab.find(b'file=')
            sig_start = jibjab.find(b'&signature=')
            MAC = hmacsha1(K.ey, jibjab[msg_start + 5: sig_start])
            sig = jibjab[sig_start + 11: ].decode("hex")

            authenticated = insecure_compare(sig, MAC)

            if authenticated: self.wfile.write("200")
            else: self.wfile.write("500")

        self.wfile.write("500")

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
    D = Delay()
    K = Key()

    try:
        D.lay = float(sys.argv[1])
        start_server()
    except:
        print "\rERROR                                "
