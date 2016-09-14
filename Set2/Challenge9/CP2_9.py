import array

text = "YELLOW SUBMARINE"

def PKCS7(text, Nbytes):
    text_array = array.array('B', text)
    N = len(text_array)
    pad = Nbytes - N
    for i in range (0, pad):
        text_array.append(pad)
    padded_text = text_array.tostring()
    return padded_text

new_text = PKCS7(text, 20)
print new_text
