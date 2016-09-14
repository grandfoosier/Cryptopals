import binascii
import array

fname = "Ex1_4.txt"
lines = [line.rstrip('\n') for line in open(fname)]

def XOR_single(tex_arr,num):
    new_tex_arr = array.array('B', tex_arr)
    for i in range (len(tex_arr)):
        #print "%i ^ %i = %i" % (tex_arr[i], num, tex_arr[i] ^ num)
        new_tex_arr[i] = tex_arr[i] ^ num
    new_tex = new_tex_arr.tostring()
    return new_tex

print ""
for Nl in range (len(lines)):
    text = binascii.unhexlify(lines[Nl])
    text_arr = array.array('B', text)
    print "line", Nl
    pause = raw_input()

    for j in range (0, 256):
        new_text = XOR_single(text_arr, j)

    pause = raw_input()
