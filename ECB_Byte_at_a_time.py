'''
Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
Detect that the function is using ECB. You already know, but do this step anyways.
Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
Repeat for the next byte.
'''

from Detect_ECB_CBC import RandAESKey
from Convert_hex_to_base64 import _64tohex  # this returns hex string
from AES_ECB import EncryptAESECB

unknownString = _64tohex('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
# unknownbytes = bytes.fromhex(_64tohex(unknownString))
Randomkey = RandAESKey(16)          # AES128 key as global variable

def AESOracle(inputtext,unknowntext=unknownString,key=Randomkey,printflag = False):
    '''
    
    :param inputtext:   in byte or hexstring
    :param unknowntext: in byte or hexstring
    :param key: in byte or string
    :return: cipher text in bytes
    '''
    if isinstance(key,str):
        key = key.encode('utf-8')
    if isinstance(unknowntext,str):
        unknowntext = bytes.fromhex(unknowntext)
    if isinstance(inputtext,str):
        inputtext = bytes.fromhex(inputtext)
    array = bytearray(inputtext)
    array.extend(unknowntext)
    plaintext = bytes(array)
    ciphertext = EncryptAESECB(key,plaintext,printflag=printflag)

    if printflag:
        print('Plaintext is:    {}'.format(plaintext))
        print('Encrypted test is:   {}'.format(ciphertext))

    return ciphertext


class DecypherAESECB:
    def __init__(self):
        # self.blocktext = blocktext.encode('utf-8')          # in bytes
        self.key = ''
        self.blocksize = -1
        self.firstblock = -1
        self.plaintext = bytearray()
        self.ECBflag = False
        self.cypherdict = {}

    def FindBlockSize(self,printflag = False):
        length = 256        # upper limit of test key length in bytes
        initialinput = 'A'
        input = initialinput
        initialcipher = AESOracle(initialinput.encode('utf-8'))
        prevlen = len(initialcipher)
        initflag = False
        firstblock = -1
        for i in range(1,length):
            input+='A'
            cipher = AESOracle(input.encode('utf-8'))
            if len(cipher)>prevlen:                  # block increased
                if not initflag:                    # is it the first block
                    initflag = True
                    prevlen = len(cipher)
                    self.firstblock = i
                else:                               # passed first block, comparing 2nd and 3rd
                    self.blocksize = i-self.firstblock
                    break
        if printflag:
            print('Block size is {}'.format(self.blocksize))

    def DetectECB(self,printflag = False):
        if self.blocksize<=0:
            print('Error, find block size first!')
        else:
            # input2 = 'A'*(self.firstblock+self.blocksize)
            input3 = 'A'*(self.firstblock + 2*self.blocksize)
            # cypher2 = bytearray(AESOracle(input2.encode('utf-8')))
            cypher3 = bytearray(AESOracle(input3.encode('utf-8')))
            if cypher3[0:self.blocksize]==cypher3[self.blocksize:2*self.blocksize]:   # same input gives same output --- ECB
                self.ECBflag = True

            if printflag:
                # print('Cypher 2nd block gives {}'.format(cypher3[0:self.blocksize]))
                # print('Cypher 3rd block gives {}'.format(cypher3[self.blocksize:2*self.blocksize]))
                print('Encoded in ECB' if self.ECBflag else 'Not Encoded in ECB')

    def GenerateDict(self,input,printflag = False):
        '''
        Input + 1 byte as input to oracle, use cipher text bytes as key of dictionary
        :param input: input string in bytes
        :param printflag:
        :return:
        '''
        self.cypherdict = {}            # empty dictionary
        for i in range(128):
            singlebyte = chr(i).encode('utf-8')
            # if isinstance(input,str):
            #     input = input.encode('utf-8')
            inputbyte = bytearray(input)
            inputbyte.extend(singlebyte)
            inputbyte = bytes(inputbyte)
            endlocation = len(inputbyte)
            dictkey = bytearray(AESOracle(inputbyte))[endlocation-self.blocksize:endlocation]
            self.cypherdict[bytes(dictkey)] = singlebyte

        if printflag:
            print(self.cypherdict)

    def BreakAESECB(self,printflag=False):
        self.FindBlockSize()
        self.DetectECB()
        textlen = len(AESOracle(b''))-self.firstblock
        if not self.ECBflag:
            print('Not ECB encoded')
        else:
            iter = 0
            while iter< textlen-1:                # iter indicates the position in encrypted text that's been decrypted

                for i in range(self.blocksize):
                    astring = 'A'*(self.blocksize-i-1)
                    curstr = astring+bytes(self.plaintext).decode()
                    self.GenerateDict(curstr.encode('utf-8'))
                    cipher = bytearray(AESOracle(astring.encode('utf-8')))[iter-i:iter+self.blocksize-i]
                    currentbyte = self.cypherdict[bytes(cipher)]
                    self.plaintext.extend(currentbyte)
                    iter+=1
                    if iter==textlen-1:
                        break

        if printflag:
            print('plaintext is {}'.format(self.plaintext))

def main():
    a = DecypherAESECB()
    a.FindBlockSize(printflag=True)
    a.DetectECB(printflag=True)
    a.BreakAESECB(printflag=True)


if __name__=='__main__':
    # print(bytes.fromhex(unknownString))
    main()