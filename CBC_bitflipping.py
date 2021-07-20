'''
CBC bitflipping attacks
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="
.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"
The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

Completely scrambles the block the error occurs in
Produces the identical 1-bit error(/edit) in the next ciphertext block.
'''

from Detect_ECB_CBC import RandAESKey
from Fixed_XOR import bufferXOR
from AES_CBC import EncryptAESCBC, DecryptAESCBC
from PKCS7_padding import padtext

globalkey = RandAESKey(16)
IV = RandAESKey(16)
prefix = "comment1=cooking%20MCs;userdata="
suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
target = b';admin=true;'


def Encryption(inputtext,printflag=False):
    '''

    :param inputtext: string
    :return:
    '''
    result = b''
    if not isinstance(inputtext,str):
        print('Wrong input, need string')
    else:
        text = prefix + inputtext + suffix
        text = text.replace(';','')
        text = text.replace('=','')
        result = EncryptAESCBC(globalkey,text.encode('utf-8'),IV,printflag=printflag)

    return result

def Decryption(ciphertext,printflag=False):
    '''

    :param ciphertext: in bytes
    :param printflag:
    :return:
    '''
    result = DecryptAESCBC(globalkey,ciphertext,IV,printflag=printflag)

    if target in result:
        print('admin in string')
        return True
    else:
        print('admin not in string')
        return False


class CrackAESCBC:
    '''
    Suppose we know the prefix as b'comment1cooking%20MCsuserdata', as well as encryption using AES CBC with block size 16
    Now we want to play with the inputtext and modify the cipher text to yield a decryption containing b';admin=true;'
    '''
    def __init__(self):
        self.key = ''
        self.blocksize = 16
        self.firstblock = -1
        self.prefixlen = len(b'comment1cooking%20MCsuserdata')
        self.plaintext = bytearray()
        self.cypherdict = {}

    def crack(self):
        '''
        General strategy would be to use two consecutive blocks with known input texts, so the 2nd cipher block is the decryption XOR with previous
        By modifying the 1st cipher block we can yield the desired 2nd block that contains the target
        :return:
        '''
        prepad = 'A'*(self.blocksize-self.prefixlen%self.blocksize)
        startpos = self.prefixlen+len(prepad)                   # should be multiple of block size
        firstblock = 'A'*self.blocksize
        secondblock = 'B'*self.blocksize
        inputtext = (prepad+firstblock+secondblock)
        ciphertext = Encryption(inputtext)
        blockc1 = ciphertext[startpos:startpos+self.blocksize]
        tail = ciphertext[startpos+self.blocksize:]
        Deblockc2 = bufferXOR(blockc1,secondblock.encode('utf-8'))
        Target = padtext(target,self.blocksize)
        modc1 = bufferXOR(Deblockc2,Target)

        result = bytearray(ciphertext[:startpos])
        result.extend(modc1)
        result.extend(tail)
        return bytes(result)

def main():
    ciphertext = Encryption('jabberwocky',printflag=True)
    Decryption(ciphertext,printflag=True)

    Crack = CrackAESCBC()
    modcipher = Crack.crack()
    Decryption(modcipher,printflag=True)

if __name__=='__main__':
    main()