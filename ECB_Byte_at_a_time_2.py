'''
Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.
'''

import random
from AES_ECB import EncryptAESECB,DecryptAESECB
from Detect_ECB_CBC import RandAESKey
from Convert_hex_to_base64 import _64tohex

globalkey = RandAESKey(16)
length = random.randint(1,100)          # less than 100 bytes
globalprefix = RandAESKey(length)
unknownString = _64tohex('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
# unknownbytes = bytes.fromhex(_64tohex(unknownString))


def AESOracle2(inputtext, prefix = globalprefix,unknowntext=unknownString, key=globalkey, printflag=False):
    '''

    :param inputtext:   in byte or hexstring
    :param prefix:  in byte or hexstring
    :param unknowntext: in byte or hexstring
    :param key: in byte or string
    :return: cipher text in bytes
    '''
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(unknowntext, str):
        unknowntext = bytes.fromhex(unknowntext)
    if isinstance(prefix,str):
        prefix = bytes.fromhex(prefix)
    if isinstance(inputtext, str):
        inputtext = bytes.fromhex(inputtext)
    array = bytearray(prefix)
    array.extend(inputtext)
    array.extend(unknowntext)
    plaintext = bytes(array)
    ciphertext = EncryptAESECB(key, plaintext, printflag=printflag)

    if printflag:
        print('Plaintext is:    {}'.format(plaintext))
        print('Encrypted test is:   {}'.format(ciphertext))

    return ciphertext


class DecypherAESECB2:
    def __init__(self):
        self.key = ''
        self.blocksize = -1
        self.firstblock = -1
        self.prefixlen = -1
        self.plaintext = bytearray()
        self.ECBflag = True                     # skipped ECB verification here
        self.cypherdict = {}

    def FindBlockSize(self,printflag = False):
        length = 256        # upper limit of test key length in bytes
        initialinput = 'A'
        input = initialinput
        initialcipher = AESOracle2(initialinput.encode('utf-8'))
        prevlen = len(initialcipher)
        initflag = False
        for i in range(1,length):
            input+='A'
            cipher = AESOracle2(input.encode('utf-8'))
            if len(cipher)>prevlen:                  # block increased
                if not initflag:                    # is it the first block
                    initflag = True
                    prevlen = len(cipher)
                    self.firstblock = i             # pad length when no input
                else:                               # passed first block, comparing 2nd and 3rd
                    self.blocksize = i-self.firstblock
                    break
        if printflag:
            print('Block size is {}'.format(self.blocksize))

    def findfirstdiffblock(self,cipher1,cipher2,printflag=False):
        '''

        :param cipher1: cipher text in bytes
        :param cipher2:
        :return:
        '''
        if self.blocksize<=0:
            raise ValueError("Run FindBlockSize first!")
        for i in range(int(min(len(cipher1)/self.blocksize,len(cipher2)/self.blocksize))):
            if cipher1[i*self.blocksize:(i+1)*self.blocksize]!=cipher2[i*self.blocksize:(i+1)*self.blocksize]:
                break
        if printflag:
            print('total block in cypher1 is {}, in cypher2 is {}'.format(int(len(cipher1)/self.blocksize),int(len(cipher2)/self.blocksize)))
            print('First different block is {}'.format(i))
        return i

    def FindPrefixLength(self,printflag= False):
        if self.blocksize <=0:
            self.FindBlockSize()
        length = 2*self.blocksize
        initialinput = 'A'
        input = initialinput
        initialcipher = AESOracle2(initialinput.encode('utf-8'))
        testcipher = AESOracle2((initialinput+'A').encode('utf-8'))
        blockstart = self.findfirstdiffblock(testcipher,initialcipher)
        prevblockval = initialcipher[blockstart*self.blocksize:(blockstart+1)*self.blocksize]
        for i in range(1, length):
            input += 'A'
            cipher = AESOracle2(input.encode('utf-8'))
            if cipher[blockstart*self.blocksize:(blockstart+1)*self.blocksize]==prevblockval:  # block increased
                self.prefixlen = (blockstart+1)*self.blocksize - i
                break
            else:
                prevblockval = cipher[blockstart*self.blocksize:(blockstart+1)*self.blocksize]

        if printflag:
            print('Prefix length is {}'.format(self.prefixlen))

    def GenerateDict(self, input, printflag=False):
        '''
        Input + 1 byte as input to oracle, use cipher text bytes as key of dictionary
        :param input: input string in bytes
        :param printflag:
        :return:
        '''
        self.cypherdict = {}  # empty dictionary
        for i in range(128):
            singlebyte = chr(i).encode('utf-8')
            # if isinstance(input,str):
            #     input = input.encode('utf-8')
            inputbyte = bytearray(input)
            inputbyte.extend(singlebyte)
            inputbyte = bytes(inputbyte)
            endlocation = len(inputbyte)+self.prefixlen                     # because there's prefix added
            dictkey = bytearray(AESOracle2(inputbyte))[endlocation - self.blocksize:endlocation]
            self.cypherdict[bytes(dictkey)] = singlebyte

        if printflag:
            print(self.cypherdict)

    def BreakAESECB(self,printflag=False):
        self.FindBlockSize()
        self.FindPrefixLength()
        a=len(AESOracle2(b''))
        textlen = len(AESOracle2(b''))-self.firstblock-self.prefixlen
        filllen = self.blocksize-self.prefixlen%self.blocksize if self.prefixlen%self.blocksize else 0
        if not self.ECBflag:
            print('Not ECB encoded')
        else:
            iter = 0
            while iter< textlen-1:                # iter indicates the position in encrypted text that's been decrypted

                for i in range(self.blocksize):
                    astring = 'A'*(self.blocksize-i-1+filllen)          # fill A to prefix till block multiple, then add A's like in previous byte-at-a-time
                    curstr = astring+bytes(self.plaintext).decode()
                    self.GenerateDict(curstr.encode('utf-8'))
                    cipher = bytearray(AESOracle2(astring.encode('utf-8')))[iter-i+filllen+self.prefixlen:iter+self.blocksize-i+filllen+self.prefixlen]
                    currentbyte = self.cypherdict[bytes(cipher)]
                    self.plaintext.extend(currentbyte)
                    iter+=1
                    if iter==textlen-1:
                        break
        if printflag:
            print('plaintext is {}'.format(self.plaintext))

def main():
    a=DecypherAESECB2()
    a.BreakAESECB(printflag=True)


if __name__=='__main__':
    main()