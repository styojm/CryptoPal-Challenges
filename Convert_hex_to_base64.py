'''
Convert hex to base64
The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
'''

import base64

hexstring = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
hexstring2 = '746865206b696420646f6e277420706c6179'
b64string = 'HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS'

def hexto64(input,printflag = False):
    '''
    input is a hex string (not a hex number) in ascii
    '''
    try:
        message_bytes = bytes.fromhex(input)
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('utf-8')       # in ascii
        if printflag:
            print('original message is {}'.format(input))
            print('binary_bytes is {}'.format(message_bytes))
            print('base64_bytes is {}'.format(base64_bytes))
            print('base64_message is {}'.format(base64_message))
        return base64_message
    except ValueError:
        print('Error hex conversion, verify validity of input')
        return ''

def _64tohex(input,printflag=False):
    '''
    Change input from 64 to hex string
    :param input:
    :param printflag:
    :return:
    '''
    try:
        base64_bytes = base64.b64decode(input)
        hex_message = base64_bytes.hex()
        if printflag:
            print('original message is {}'.format(input))
            print('hex_message is {}'.format(hex_message))
        return hex_message
    except ValueError:
        print('Error in decoding, verify validity of input')
        return ''

if __name__=='__main__':
    hexto64(hexstring,True)
    _64tohex(b64string,True)