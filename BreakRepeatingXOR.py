'''
Break repeating-key XOR
It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
this is a test
and
wokka wokka!!!
is 37. Make sure your code agrees before you proceed.
For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
Solve each block as if it was single-character XOR. You already have code to do this.
For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
'''

import bitarray
import Convert_hex_to_base64 as CHB64
import Single_byte_XOR_cipher as SBXOR
import numpy as np

teststring1 = 'this is a test'
teststring2 = 'wokka wokka!!!'

filepath = r'C:\Users\styojm\PycharmProjects\crypto\S1C6.txt'

def HammingDistance(str1,str2):
    '''
    return the hamming distance (bitwise) between two strings
    :param str1:
    :param str2:
    :return:
    '''
    ba1 = bitarray.bitarray()
    ba2 = bitarray.bitarray()
    ba1.frombytes(str1.encode('utf-8'))
    ba2.frombytes(str2.encode('utf-8'))
    dist = len(ba1)-len(ba2)
    for i in range(min(len(ba1),len(ba2))):
        if ba1[i]!=ba2[i]:
            dist+=1

    return dist

def KeySizeCheck(text,sizerange=(2,40),printflag = False):
    '''

    :param text: input text in hex string
    :param sizerange:
    :return:
    '''
    sizemin = 0.0
    sizemax = 0.0
    text = bytearray(bytes.fromhex(text))
    try:
        sizemin = sizerange[0]
        sizemax = sizerange[1]
    except ValueError:
        print('Wrong size range')
        return 0
    mindist = 1E8
    minkeysize = -1
    keydist = []
    for keysize in range(sizemin,sizemax+1):
        length = min(5,int(len(text)/2/keysize))
        dist = 0
        for i in range(length):
            bytestr1 = text[2*i*keysize:2*i*keysize+keysize]
            bytestr2 = text[(2*i+1)*keysize:2*(i+1)*keysize]
            dist += HammingDistance(bytestr1.decode(),bytestr2.decode())
        dist = dist / length /keysize       # average
        # if dist<mindist:
        #     mindist = dist
        #     minkeysize = keysize
        keydist.append((dist,keysize))
        keydist.sort(key=lambda x: x[0])
        mindist = keydist[0][0]
        minkeysize = keydist[0][1]

    if printflag:
        print('Min dist is {}, keysize is {}'.format(mindist,minkeysize))
    return mindist,minkeysize,keydist

def Decypher(text,keysize,printflag = False):
    '''

    :param text: Input encrypted text in hex string
    :param keysize:
    :param printflag:
    :return:
    '''
    key = ''
    plaintext = ''
    textbytearray = bytearray(bytes.fromhex(text))
    if keysize<=0 or keysize > len(textbytearray):
        print('Keysize Error')
        return key, plaintext
    textarray=[]
    keyarray = []
    for i in range(keysize):
        block = textbytearray[i::keysize]
        minscore,besttext,curkey = SBXOR.FindBestPlainText(bytes(block).hex(), False)
        # print(minscore,'    ',curkey,'  ',besttext)
        textarray.append(besttext)
        keyarray.append(curkey)

    # assemble text and key
    for i in range(len(keyarray)): key+=keyarray[i]
    for j in range(len(textarray[0])):          # first text is always the longest
        for k in range(keysize):
            if j<len(textarray[k]):
                plaintext+=textarray[k][j]
    return key,plaintext

def main():
    with open(filepath) as file:
        data = file.read().replace('\n','')
        # data=file.read()
        hexstring = CHB64._64tohex(data)
        mindist,keysize,keydist = KeySizeCheck(hexstring)
        minscore = 1E12
        mintext = ''
        minkey = ''
        for i in range(5):                  # check first 5 keysize
            ksize = keydist[i][1]
            key,plaintext = Decypher(hexstring,ksize)
            score = SBXOR.SimpleTextScore(plaintext)
            if score<minscore:
                minscore = score
                mintext = plaintext
                minkey = key

        print('Final key is:    {}'.format(minkey))
        print('Final text is:   {}'.format(mintext))

if __name__=='__main__':
    main()
