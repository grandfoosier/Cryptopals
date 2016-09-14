import re
from Crypto.Cipher import AES
import array
from random import randint

coded = "foo=bar&baz=qux&zap=zazzle"
email1 = "foo@bar.com"
email2 = "foo@bar.com&role=admin"

mode = AES.MODE_ECB
zeroskey = 16 * '\x00'
IV = 16 * '\x00'
encryptor = AES.new(zeroskey, mode)
decryptor = AES.new(zeroskey, mode)

################################################################

def kv_parse(coded):
    output = "{"
    s = coded
    a = '&'
    e = '='
    ands = [pos for pos,
        char in enumerate(s) if char == a]

    if len(ands) >= 1:
        s_0 = s[0:ands[0]]
        equals = [pos for pos,
            char in enumerate(s_0) if char == e]

        X = ""
        val = s_0[equals[0]+1:len(s_0)]
        try: val = int(val)
        except: X = "'"

        assert len(equals) == 1
        output = output + s_0[0:equals[0]] + ": %s" % X
        output = output + str(val) + "%s, " % X

        for i in range (0, len(ands)):
            if len(ands) >= i + 2:
                s_i = s[ands[i]+1:ands[i + 1]]
                equals = [pos for pos,
                    char in enumerate(s_i) if char == e]

                X = ""
                val = s_i[equals[0]+1:len(s_i)]
                try: val = int(val)
                except: X = "'"

                assert len(equals) == 1
                output = output + s_i[0:equals[0]] + ": %s" % X
                output = output + str(val) + "%s, " % X

            else:
                s_i = s[ands[i]+1:len(s)]
                equals = [pos for pos,
                    char in enumerate(s_i) if char == e]

                X = ""
                val = s_i[equals[0]+1:len(s_i)]
                try: val = int(val)
                except: X = "'"

                assert len(equals) == 1
                output = output + s_i[0:equals[0]] + ": %s" % X
                output = output + str(val) + "%s}" % X

    else:
        equals = [pos for pos,
            char in enumerate(s) if char == e]

        X = ""
        val = s[equals[0]+1:len(s)]
        try: val = int(val)
        except: X = "'"

        assert len(equals) == 1
        object[s[0:equals[0]]] = s[equals[0]+1:len(s)]
        output = output + s[0:equals[0]] + ": %s" % X
        output = output + str(val) + "%s}" % X

    return output

def kv_encode(string):
    encoded = ""
    delimited = string[1:-1].split(", ")

    for i in range (0, len(delimited)):
        colon = [pos for pos,
            char in enumerate(delimited[i]) if char == ':']

        val = delimited[i][colon[0]+2:]
        if ((val[0] == val[-1]) and
                ((val[0] == "'") or (val[0] == '"'))):
            val = val[1:-1]

        encoded = encoded + delimited[i][0:colon[0]] + "="
        encoded = encoded + val + "&"
    return encoded[0:len(encoded)-1]
    
def profile_for(email):
    stripped_email = re.sub('[&=]', '', email)
    json_string = "{email: '%s', uid: 10, role: 'user'}" % stripped_email
    encoded = kv_encode(json_string)
    return encoded

def gen_key():
    key = array.array('B', [])
    for i in range (0, 16):
        key.append(randint(0,255))
    return key.tostring()

def PKCS7(text, pad):
    text_array = array.array('B', text)
    N = len(text_array)
    for i in range (0, pad):
        text_array.append(pad)
    padded_text = text_array.tostring()
    return padded_text

def PKCS7_check(text):
    pad = ord(text[-1])
    assert len(text) > pad
    check = 0
    for i in range (0, pad):
        if ord(text[-1 - i]) == pad:
            check += 1
    if check == pad:
        return "OK"

def ECB_encrypt(text, KEY):
    encryptor = AES.new(KEY, mode)

    raw_N = len(text)
    full_blocks = raw_N / 16
    Nbytes = 16 - (raw_N - (full_blocks * 16))
    padded_text = PKCS7(text, Nbytes)

    new_text = encryptor.encrypt(padded_text)
    return new_text

def ECB_decrypt(text, KEY):
    decryptor = AES.new(KEY, mode)
    new_text = decryptor.decrypt(text)
    return new_text

def profile_encrypt(email):
    profile = profile_for(email)
    encrypt = ECB_encrypt(profile, K.ey)
    return encrypt

def profile_decrypt(string):
    decrypt = ECB_decrypt(string, K.ey)

    if PKCS7_check(decrypt) == "OK":
        pad = ord(decrypt[-1])
        decrypt = decrypt[0:pad * -1]
    parsed = kv_parse(decrypt)
    return parsed
    
class Key(object):
    def __init__(self):
        self.ey = ""
        self.icker = ""
K = Key()
K.ey = gen_key()

################################################################

# print ""
# encrypt1 = profile_encrypt(email1)
# print encrypt1
# parsed1 = profile_decrypt(encrypt1)
# print parsed1
# print ""

#1234567890ABCDEF 1234567890ABCDEF 1234567890ABCDEF 1234567890ABCDEF
#email=foo@bar.co m&uid=10&role=us erDDDDDDDDDDDDDD
#email=foose@bar. com&uid=10&role= adminAAAAAAAAAAA
uncut = profile_encrypt('foose@bar.com')
array1 = array.array('B', uncut)
left = array1[0:-16]

#1234567890ABCDEF 1234567890ABCDEF 1234567890ABCDEF 1234567890ABCDEF
#email=1234567890 adminAAAAAAAAAAA .com&uid=10&role =userAAAAAAAAAAA
emailforhack = ('123456789@' + 'admin' + ('\x0B' * 11) + '.com')
has_it = profile_encrypt(emailforhack)
array2 = array.array('B', has_it)
right = array2[16:32]

print ""
for i in range (0, len(right)):
    left.append(right[i])
hacked = left.tostring()
backdoor = profile_decrypt(hacked)
print backdoor

print ""
