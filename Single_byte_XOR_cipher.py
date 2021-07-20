'''
Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
'''

import numpy as np
import string

cypher = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
test = '7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f'

specialcharindices = [10,33,34,39,44,45,46,48,49,50,
                      51,52,53,54,55,56,57,58,59,63]

def SimpleTextScore(inputstring):
    '''
    return the score based on alphabet frequency
    :param inputstring: input string (English sentence)
    :return:
    '''
    ascchartlist=np.zeros(128)
    ascweightlist=np.ones(128)      # weight
    natural_freq = np.array([8.4966,2.072,4.5388,3.3844,11.1607,1.8121,2.4705,3.0034,7.5448,0.1965,1.1016,5.4893,3.0129,6.6544,7.1635,
                    3.1671,0.1962,7.5809,5.7351,6.9509,3.6308,1.0074,1.2899,0.2902,1.7779,0.2722])
    # adjust special character weight
    ascweightlist[0:97]*=1000
    # ascweightlist[32:65]*=1
    # # ascweightlist[65:91]*=1000
    # ascweightlist[91:97]*=1000
    ascweightlist[123:]*=1000
    for i in specialcharindices:
        ascweightlist[i]=1
    # adjust character frequency
    ascchartlist[97:123] = natural_freq
    # ascchartlist[33:65] = np.ones(32)*0.1               # assume 0.1% character occurance
    # ascchartlist[91:97] = np.ones(6)*0.1
    # ascchartlist[123:127] = np.ones(4)*0.1

    counter = np.zeros(128)      # record
    lowercasestring = inputstring.lower()
    lowercasestring = lowercasestring.replace(' ','')
    lowercasestring = lowercasestring.strip('')
    for i in range(128):
        counter[i] = lowercasestring.count(chr(i))/len(lowercasestring)*100
    # if np.sum(counter)!=0:
    #     counter = counter/np.sum(counter)*100           # percentage of occurance
    # else:
    #     return 1000         # large number

    score = np.sqrt(np.sum(np.square((counter-ascchartlist)*ascweightlist)))
    # score = score * (np.sum())
    return score

def byteXOR(text,key):
    '''
    return
    :param text: Input hex string
    :param key: encode char (int)
    :return:
    '''
    byte_hex = bytes.fromhex(text)
    byte_array = bytearray(byte_hex)
    for i in range(len(byte_array)):
        byte_array[i]^=key
    return byte_array


def FindBestPlainText(cyphertext,printflag=False):
    '''
    Find the most likely single-char encrypted original text and key
    :param cyphertext: input encrypted hex text
    :param printflag: print result or not
    :return: tuple of (minscore, best_text, key)
    '''
    minscore = 1E12
    besttext = 'Unknown'
    curkey = 'Unknown'
    for key in range(128):
        outarray = byteXOR(cyphertext, key)

        try:
            outstring = outarray.decode()
            score = SimpleTextScore(outstring)
            # print(' ',score,'   ',outstring)
            if score<minscore:
                minscore = score
                besttext = outstring
                curkey = chr(key)
        except UnicodeDecodeError:
            if printflag:
                print('Decode error')
    if printflag:
        print('Original hex message is: {}'.format(cypher))
        print('Best matching key is:    {}'.format(curkey))
        print('Original message is: {}'.format(besttext))

    return minscore,besttext,curkey

if __name__=='__main__':
    FindBestPlainText(test,True)