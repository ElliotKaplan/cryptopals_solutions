from binascii import unhexlify
from collections import Counter
from string import ascii_letters, printable

from Crypto.Util.strxor import strxor_c

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
        count = Counter(decipher)
        score = sum(count[k] for k in most_common)
        if score > highscore:
            highscore = score
            truekey = key
    # if no key actually works, return None
    try:
        return truekey
    except NameError:
        return None

ciphertext = unhexlify(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
key = highscore_xor(set(printable.encode()), ciphertext)
print(chr(key))
print(strxor_c(ciphertext, key))
