from hashlib import sha1
import time
import web
import subprocess
import socket
import sys
from binascii import hexlify
from CP4_31_server import strxor, hmacsha1

#######################################################################
# Setup classes (delay less than .02 may not work)
class Files(object):
    def __init__(self):
        self.ile = "C:/Users/rices/Coding/CP4_31_server.py "
class Delay(object):
    def __init__(self):
        self.lay = 0.05

#######################################################################
# Connects to server, tries bytes until delay increases
def obtain_MAC(File):
    HOST, PORT = "localhost", 9000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try: sock.connect((HOST, PORT))
    except: print "Could not connect to server"

    MAC = bytearray('')
    predata = b'test?file=' + bytearray(File) + b'&signature='

    for i in range (0, 20):
        for j in range (0, 256):
            MACguess = bytearray(''); MACguess[:] = MAC
            MACguess.extend(chr(j).encode("hex"))
            MACguess.extend("0" * (40 - len(MACguess)))

            data = predata + MACguess + b'\n'

            start = time.time()
            sock.sendall(data)
            received = sock.recv(1024)
            stop = time.time()

            print ("\r%s   %s   %s" % (MACguess, str(stop-start)[:5],
                   str((stop - start) / D.lay + .1)[:5])),

            if int((stop - start) / D.lay + .1) > i:
                MAC.extend(chr(j).encode("hex"))
                break

    print "\n\n" + received

    return MAC

#######################################################################
# Main routine (also opens subprocess)
if __name__ == "__main__":
    print ""
    F = Files()
    D = Delay()

    args = [F.ile, str(D.lay)]
    subprocess.Popen([sys.executable, args])

    time.sleep(1)
    print "\nParent process running...\n"

    MAC = obtain_MAC("foo")

    print "\n"
