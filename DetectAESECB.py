'''
Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

Strategy is to separate in 16-byte block, and detect repetition
'''

from AES_ECB import DecryptAESECB
from Single_byte_XOR_cipher import SimpleTextScore
import math

filepath = r'C:\Users\styojm\PycharmProjects\crypto\S1C8.txt'

def RepeatCount(text,blocksize=16):
    '''

    :param text:    text in hexstring
    :param blocksize: block size/length
    :return: the repeat count normalized to the block #
    '''
    byte_message = None    # if text is in bytes
    if isinstance(text,str):
        byte_message = bytearray(bytes.fromhex(text))
    else:
        byte_message = bytearray(text)
    messagelist = []
    blockNum = math.ceil(len(text)/blocksize)
    for i in range(blockNum):
        messagelist.append(text[i*blocksize:(i+1)*blocksize])
    messagelist.sort()

    repeatcount = 0
    for i in range(1,len(messagelist)):
        if messagelist[i]==messagelist[i-1]:
            repeatcount+=1

    return repeatcount/blockNum

def main():
    with open(filepath) as file:
        lines = file.readlines()             # hex strings
        maxcount = -1
        message = ''
        for line in lines:
            count = RepeatCount(line)
            if count>maxcount:
                maxcount = count
                message = line
        print('Repeatcount {}, for message {}'.format(maxcount,message))

if __name__ == '__main__':
    main()