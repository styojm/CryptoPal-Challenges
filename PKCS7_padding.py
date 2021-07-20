'''
Implement PKCS#7 padding
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
'''

from Crypto.Util.Padding import pad,unpad

text = 'YELLOW SUBMARINE'

def padtext(text,blocksize,style='pkcs7',printflag = False):
    '''

    :param text: normal string or bytes
    :param blocksize:  size of block to pad
    :param style:
    :return: padded text in bytes
    '''
    data = text
    if isinstance(text,str):
        data = text.encode('utf-8')
    padding = pad(data,blocksize,style)
    if printflag:
        print('Original text is:    {}'.format(text))
        print('Padded text is:  {}'.format(padding))

    return padding

def unpadtext(text,blocksize,style='pkcs7',printflag = False):
    '''

    :param text:    padded text in string or bytes
    :param blocksize: size of block when padded
    :param style:
    :param printflag:
    :return: unpadded text in bytes
    '''
    data = text
    if isinstance(text,str):
        data = text.encode('utf-8')
    unpadding = unpad(data,blocksize,style)
    if printflag:
        print('Padded text is:    {}'.format(text))
        print('Unpadded text is:    {}'.format(unpadding))

    return unpadding

if __name__=='__main__':
    txt = padtext(text,20,printflag=True)
    unpadtext(txt,20,printflag=True)
