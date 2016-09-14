def PKCS7_check(text):
    pad = ord(text[-1])
    assert len(text) > pad
    check = 0
    for i in range (0, pad):
        if ord(text[-1 - i]) == pad:
            check += 1
    assert check == pad
    new_text = text[0:pad * -1]
    return new_text

text1 = "ICE ICE BABY\x04\x04\x04\x04"
text2 = "ICE ICE BABY\x05\x05\x05\x05"
text3 = "ICE ICE BABY\x01\x02\x03\x04"

print PKCS7_check(text1)
#print PKCS7_check(text2)
#print PKCS7_check(text3)
