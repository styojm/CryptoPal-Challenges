'''
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
'''

from ECB_Byte_at_a_time import AESOracle,DecypherAESECB
from AES_ECB import EncryptAESECB,DecryptAESECB
from Detect_ECB_CBC import RandAESKey

globalkey = RandAESKey(16)


def kvparsing(inputstring):
    '''
    input string is separated by '&'
    :param inputstring:
    :return:
    '''
    if not isinstance(inputstring,str):
        print('Erroneous input, not a string')
        return {}
    else:
        elements = inputstring.split('&')
        dict = {}
        for i in elements:
            lhs = i.split('=')[0]
            rhs = i.split('=')[1]
            dict[lhs]=rhs
        return dict

def profile_for(emailstring):
    '''

    :param emailstring:
    :return:        string of the encoded user profile
    '''
    if not isinstance(emailstring,str):
        print('Error input email string')
    emailstring = emailstring.split('&')[0]               # remove stuff after encoding metacharacter &
    emailstring = emailstring.split('=')[0]                # remove stuff after encoding metacharacter =
    dict = {'email':'','uid':10,'role':'user'}
    dict['email']=emailstring
    encodedtext = 'email={0}&uid={1}&role={2}'.format(dict['email'],dict['uid'],dict['role'])
    return encodedtext

def Encryptprofile(emailstring,printflag=False):            # function that's visible to the attacker
    encodedtext = profile_for(emailstring)
    encryptedtext = EncryptAESECB(globalkey,encodedtext.encode('utf-8'))
    if printflag:
        print('Encrypted profile is:    {}'.format(encryptedtext))
    return encryptedtext

def Decryptprofile(encryptedtext,printflag = False):
    '''
    convert encrypted bytes into user profile
    :param encryptedtext:
    :return:
    '''
    encodedtext = DecryptAESECB(globalkey,encryptedtext)
    text = encodedtext.decode()
    dict = kvparsing(text)
    if printflag:
        print('Decrypted profile is:    {}'.format(dict))

class Generateadminprofile:
    '''
    Assume that we know the message format 'email=emailstring ... role=user', and the padding scheme is PKCS7 with encryption block size = 16
    Use only Encryptprofile function and the cipher text to generate admin profile cipher text
    '''
    def __init__(self):
        self.blocksize = 16
        self.prefix = 6
        self.suffix = 13
        self.email='eve@gmail.com'          # len(self.email)=2*self.blocksize-self.prefix-self.suffix

    # def FindBlockSize(self,printflag = False):
    #     length = 256        # upper limit of test key length in bytes
    #     initialinput = 'A'
    #     input = initialinput
    #     initialcipher = Encryptprofile(initialinput)
    #     prevlen = len(initialcipher)
    #     initflag = False
    #     for i in range(1,length):
    #         input+='A'
    #         cipher = Encryptprofile(input)
    #         if len(cipher)>prevlen:                  # block increased
    #             if not initflag:                    # is it the first block
    #                 initflag = True
    #                 prevlen = len(cipher)
    #                 self.firstblock = i
    #             else:                               # passed first block, comparing 2nd and 3rd
    #                 self.blocksize = i-self.firstblock
    #                 break
    #     self.infolength = len(initialcipher) - self.firstblock
    #     if printflag:
    #         print('Block size is {}, Info length is {}'.format(self.blocksize,self.infolength))

    def Generatefakeprofile(self):
        '''
        Need to know at least the encoded string structure --- 'email=emailstring ... role=user'
        :return:
        '''
        adminstr = 'admin'
        head = 'A'*(self.blocksize-self.prefix)
        fake1 = Encryptprofile(head+adminstr)
        cyphertail = fake1[self.blocksize:2*self.blocksize]          # to be appended at the end

        fake2 = Encryptprofile(self.email)                    # set 'admin' at the position after 'role='
        cypherhead = fake2[0:-self.blocksize]

        resultprofile = bytearray(cypherhead)
        resultprofile.extend(cyphertail)
        return bytes(resultprofile)




    # encrypt1 = Encryptprofile(emailstring)              # generate eve profile as user
    # length = len(encrypt1)-4        # length till 'role='
    # encrypt2 = Encryptprofile('A'*length+'admin')
    # usefulpart = encrypt2[length:length+5]          # include the 'admin' encrypted
    # resultprofile = bytearray(encrypt1)[0:length]
    # resultprofile.extend(usefulpart)
    # return bytes(resultprofile)


def main():
    message = Encryptprofile('yujie@gmail.com&role=admin',printflag=True)
    dict = Decryptprofile(message,printflag=True)

    a = Generateadminprofile()
    fakeprofile = a.Generatefakeprofile()
    dict = Decryptprofile(fakeprofile,printflag=True)

if __name__=='__main__':
    main()