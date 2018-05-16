from string import printable
from collections import Counter

import numpy as np
from Crypto.Util.strxor import strxor, strxor_c

most_common = set(b'etaoin shrdlu')
unprintable = set(range(0x100)).difference(set(printable.encode()))

def highscore_xor(keyspace, ciphertext):
    # returns the key with the highest number of characters in the most_common
    # set, and no unprintable characters

    # any character in the ciphertext is excluded as null byte generating
    keyspace = keyspace.difference(set(ciphertext))
    highscore = 0
    for key in keyspace:
        decipher = strxor_c(ciphertext, key)
        # skip if there are any unprintable characters
        if any(c in unprintable for c in decipher):
            continue
        count = Counter(decipher.lower())
        score = sum(count[k] for k in most_common)
        if score > highscore:
            highscore = score
            truekey = key
    # if no key actually works, return None
    try:
        return truekey
    except NameError:
        return None

def repeating_xor(key, plaintext):
    # computes the xor of the plaintext with a repeating key
    keylen = len(key)
    split_text = (plaintext[i::keylen] for i in range(keylen))
    xor_split = tuple(strxor_c(txt, k) for txt, k in zip(split_text, key))
    # have to encode the text becaue python3 is puts the characters into
    # unicode strings
    xor_text = ''.join(''.join(map(chr, t)) for t in zip(*xor_split)).encode()
    # if the key doesn't match the text length exactly, add in the last
    # characters from 
    remainder = len(plaintext) % keylen
    xor_text += ''.join(chr(s[-1]) for s in xor_split[:remainder]).encode()
    return xor_text

def hamming_distance(string1, string2):
    # hamming distance is defined as the count of different bits, use the xored
    # of the two strings to calculate this
    xorstring = strxor(string1, string2)
    xorarr = np.fromstring(xorstring, np.uint8)
    # compute the number of 1 bits in the xorstring
    dist = sum(((xorarr & i) // i).sum()
               for i in np.power(2, np.arange(8)))
    return dist
        
