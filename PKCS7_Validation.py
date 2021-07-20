'''
Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"
... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"
... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"
If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
'''

def PKCS7Unpad(inputstring,printflag= False):
    '''
    If not PKCS7 padded, return the string, else strip the padding and return the modified string
    :param inputstring: in string or bytes
    :return:
    '''
    if isinstance(inputstring,str):
        inputstring = inputstring.encode('utf-8')
    result = inputstring

    Num = inputstring[-1]
    if Num > len(inputstring):               # not padded
        print('Not padded')
    elif inputstring[-Num:]!=bytes([inputstring[-1]])*Num:
        print('Not padded')
    else:
        result = inputstring[:-Num]
    if printflag:
        print('Original string is {}\nResulting string is {}'.format(inputstring,result))

    return result

def main():
    string1 = "ICE ICE BABY\x04\x04\x04\x04"
    string2 = "ICE ICE BABY\x05\x05\x05\x05"
    string3 = "ICE ICE BABY\x01\x02\x03\x04"
    PKCS7Unpad(string1,printflag=True)
    PKCS7Unpad(string2, printflag=True)
    PKCS7Unpad(string3, printflag=True)

if __name__=='__main__':
    main()