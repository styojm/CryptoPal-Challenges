'''
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
'''


buf1 = '1c0111001f010100061a024b53535009181c'
buf2 = '686974207468652062756c6c277320657965'


def bufferXOR(buffer1,buffer2,printflag=False):
    '''
    takes two equal-length buffers and produces their XOR combination
    :param buffer1: either hex string or bytes
    :param buffer2: either hex string or bytes
    :param printflag:
    :return: XOR result in bytearray
    '''
    # verify if length is the same
    try:
        byte1 = buffer1
        byte2 = buffer2
        if isinstance(buffer1,str):
            byte1= bytes.fromhex(buffer1)
        if isinstance(buffer2,str):
            byte2 = bytes.fromhex(buffer2)

        if len(byte1)!=len(byte2):
            print('Input error, len1 {} and len2 {} do not match'.format(len(byte1),len(byte2)))
            return ''
        XOR_bytes = bytearray(byte1)
        for i,b in enumerate(byte2):
            XOR_bytes[i]^=b
        # XOR_message = XOR_bytes.decode()
        if printflag:
            print('Buffer1 is:  {}'.format(buffer1))
            print('Buffer2 is:  {}'.format(buffer2))
            print('Hex is: {}'.format(XOR_bytes.hex()))
            # print('XOR buffer is:   {}'.format(XOR_message))

        return XOR_bytes
    except ValueError:
        print('Error hex conversion, verify validity of input')
        return bytearray(b'')


if __name__=='__main__':
    bufferXOR(buf1,buf2,True)



