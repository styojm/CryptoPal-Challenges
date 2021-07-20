'''
Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
'''

from AES_ECB import DecryptAESECB,EncryptAESECB
from Fixed_XOR import bufferXOR
from PKCS7_padding import padtext,unpadtext
import Convert_hex_to_base64 as CHB64


textfile = r'C:\Users\styojm\PycharmProjects\crypto\S2C10.txt'

def DecryptAESCBC(key,ciphertext,iv,printflag = False):
    '''

    :param key: in bytes or hex string
    :param text: in bytes
    :param iv:
    :param printflag:
    :return:
    '''
    plaintext = ''.encode('utf-8')
    if isinstance(key,str):
        key = key.encode('utf-8')
    if isinstance(iv,str):
        iv = iv.encode('utf-8')
    if len(key)!=len(iv):
        print('IV length and key length do not match')
        return plaintext

    blocksize = len(key)
    if len(ciphertext)%blocksize!=0:
        print('cipher text length error, not multiple of block size')
        return plaintext
    plaintext = bytearray(len(ciphertext))
    curvec = iv
    for block in range(int(len(ciphertext)/blocksize)):
        text = ciphertext[block*blocksize:(block+1)*blocksize]
        curplaintext = DecryptAESECB(key,text,blocksize)
        curplaintext = bufferXOR(curplaintext,curvec)
        curvec = text
        plaintext[block*blocksize:(block+1)*blocksize]=curplaintext
    plaintext = bytes(plaintext)
    try:
        plaintext = unpadtext(bytes(plaintext),blocksize)
    except ValueError:
        pass

    if printflag:
        print('Decrypted text is:   {}'.format(plaintext))

    return plaintext

def EncryptAESCBC(key,text,iv,printflag=False):
    '''

    :param key:
    :param text:
    :param iv:
    :param printflag:
    :return:
    '''
    ciphertext = ''.encode('utf-8')
    if isinstance(key,str):
        key = key.encode('utf-8')
    if isinstance(iv,str):
        iv = iv.encode('utf-8')
    if len(key)!=len(iv):
        print('IV length and key length do not match')
        return ciphertext

    blocksize = len(key)
    paddedtext = padtext(text,blocksize)
    ciphertext = bytearray()
    curvec = iv
    for block in range(int(len(paddedtext)/blocksize)):
        text = bufferXOR(paddedtext[block*blocksize:(block+1)*blocksize],curvec)        # XOR
        curcipher = EncryptAESECB(key,bytes(text))
        curvec = curcipher
        ciphertext[block*blocksize:(block+1)*block] = curcipher
    if printflag:
        print('Encrypted text is:   {}'.format(ciphertext))

    return bytes(ciphertext)

def main():
    with open(textfile) as file:
        data = file.read()
        hexstring = CHB64._64tohex(data)
        IV = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        key = "YELLOW SUBMARINE"
        plaintext = DecryptAESCBC(key,bytes.fromhex(hexstring),IV)
        print('Plaintext is:    {}'.format(plaintext.decode()))

        encrypted = EncryptAESCBC(key,bytes(plaintext),IV)
        encryptedtext = bytes(encrypted).hex()
        if bytes(encrypted) == bytes.fromhex(hexstring):
            print('Encoding correctly')


if __name__=='__main__':
    main()