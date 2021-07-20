'''
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
'''

import Single_byte_XOR_cipher

filepath = r'C:\Users\styojm\PycharmProjects\crypto\S1C4.txt'

def Readstrings(file):
    '''
    Read the hex strings
    :param file:
    :return:
    '''
    strarray = list()
    with open(file) as File:
        lines = File.readlines()
        for line in lines:
            # asciiline = line.encode('ascii','ignore')
            strarray.append(line)


    return strarray


def FindMinScore(strarray,printflag = False):
    minscore = 1000
    originalstring = ''
    besttext = 'Unknown'
    key = 'Unknown'

    for string in strarray:
        cscore,ctext,ckey = Single_byte_XOR_cipher.FindBestPlainText(string,printflag)
        print(cscore,'  ',ctext,'   ',ckey)
        if cscore<minscore:
            minscore = cscore
            originalstring = string
            besttext = ctext
            key = ckey

    if printflag:
        print('Encrypted hex text is:   {}'.format(originalstring))
        print('Best matching key is:    {}'.format(key))
        print('Original text message is:    {}'.format(besttext))


    return minscore,originalstring,besttext,key

if __name__=='__main__':
    score,original,besttext,key = FindMinScore(Readstrings(filepath),printflag=False)
    print(original)
    print(besttext)
    print(key)