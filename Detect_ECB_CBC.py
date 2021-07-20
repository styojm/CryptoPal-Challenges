'''
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
'''

import random
from Crypto.Random import get_random_bytes
from AES_ECB import EncryptAESECB
from AES_CBC import EncryptAESCBC
from PKCS7_padding import padtext
from DetectAESECB import RepeatCount

testfile = r'C:\Users\styojm\PycharmProjects\crypto\S2C11.txt'

def RandAESKey(keysize = 16):
    '''
    return random key in bytes with keysize
    :param keysize: the size of the key in bytes
    :return: key in bytes
    '''
    return get_random_bytes(keysize)

def encryption_oracle(inputtext):
    '''
    encrpyts input text, append before and after plaintext
    :param inputtext:
    :return: encrypted text in bytes
    '''
    appendnum = random.randint(5,10)
    before = bytearray(RandAESKey(appendnum))
    after = bytearray(RandAESKey(appendnum))
    plaintext = before
    plaintext.extend(inputtext.encode('utf-8'))
    # plaintext = before.append(bytearray(plaintext))
    plaintext.extend(after)
    plaintext = bytes(plaintext)
    plaintext = padtext(plaintext,16)

    key = RandAESKey()
    iv = RandAESKey()
    ciphertext = ''.encode('utf-8')
    i = random.randint(0,1)
    if i==0:            # use ECB
        ciphertext = EncryptAESECB(key,plaintext)
    else:               # use CBC
        ciphertext = EncryptAESCBC(key,plaintext,iv)

    print('ECB, {}'.format(i) if i==0 else 'CBC')
    return ciphertext

def DetectECBCBC(blocktext,blocksize=16):
    '''
    Input blocktext and detect
    :param blocktext: in bytes or hexstring
    :param blocksize:
    :return:
    '''
    threshold = 0.001                    # repeatcount threshold above which will be counted as ECB
    repeatcount = RepeatCount(blocktext,blocksize)
    if repeatcount > threshold:
        print('Block is encrypted in ECB, repeatcount {}'.format(repeatcount))
    else:
        print('Block is encrypted in CBC, repeatcount {}'.format(repeatcount))

if __name__=='__main__':
    with open(testfile) as file:
        data = file.read()
        ciphertext = encryption_oracle(data)
        print(ciphertext)
        DetectECBCBC(ciphertext)