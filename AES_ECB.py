'''
AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
'''

from Crypto.Cipher import AES
import Convert_hex_to_base64 as CHB64
from PKCS7_padding import padtext,unpadtext

textfile = r'C:\Users\styojm\PycharmProjects\crypto\S1C7.txt'

def DecryptAESECB(key,text,blocksize=16,printflag = False):
    '''
    Decode the text with the key using AES ECB
    :param key: in bytes
    :param text: also in bytes (or hex string)
    :param printflag:
    :return: plaintext in bytes
    '''
    AESkey=None
    if isinstance(key,str):
        AESkey = key.encode('utf-8')
    else:
        AESkey = key
    cipher = AES.new(AESkey,AES.MODE_ECB)
    if isinstance(text,str):
        text = bytes.fromhex(text)
    plaintext=cipher.decrypt(text)
    text = plaintext
    try:
        text = unpadtext(plaintext,blocksize)
    except ValueError:                      # text not padded
        pass

    if printflag:
        print('Encrypted text is:    {}'.format(text))
        print('Decrypted text is:   {}'.format(text))

    return text

def EncryptAESECB(key,text,blocksize=16,printflag = False):
    '''
    Encode the text with the key using AES ECB
    :param key:  in bytes
    :param text:  also in bytes
    :param printflag:
    :return: encrypted text in bytes
    '''
    AESkey = None
    if isinstance(key,str):
        AESkey = key.encode('utf-8')
    else:
        AESkey = key
    cipher = AES.new(AESkey,AES.MODE_ECB)
    plaintext = padtext(text,blocksize) if len(text)%blocksize else text
    ciphertext = cipher.encrypt(plaintext)

    if printflag:
        print('Padded plaintext is:    {}'.format(plaintext))
        print('Encrypted text is:   {}'.format(ciphertext))

    return ciphertext

def main():
    EncryptAESECB("Yellow submarine",'I am not alone'.encode('utf-8'),printflag=True)
    with open(textfile) as file:
        data = file.read().replace('\n','')
        hexstring = CHB64._64tohex(data)
        plaintext = DecryptAESECB(b"YELLOW SUBMARINE",bytes.fromhex(hexstring),printflag=True)
        print(plaintext.decode())

        encrypted = EncryptAESECB(b"YELLOW SUBMARINE",plaintext,printflag=False)
        if bytes.fromhex(hexstring) == encrypted:
            print('Encoding correctly')

def test():
    a='email=eve@gmail.com&uid=10&role=user'
    b='email=eve@gmail.com&uid=10=role=user'
    c=EncryptAESECB("YELLOW SUBMARINE",a.encode('utf-8'),printflag=True)
    d=EncryptAESECB("YELLOW SUBMARINE",b.encode('utf-8'),printflag=True)
    print(c.hex())
    print(d.hex())
    print(len(a)-len(c))
    print(len(c))
    print(len(c.hex()))

if __name__=='__main__':
    test()