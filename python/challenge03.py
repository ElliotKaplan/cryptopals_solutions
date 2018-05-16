from binascii import unhexlify
from collections import Counter
from string import ascii_letters, printable

from Crypto.Util.strxor import strxor_c

from utilities import highscore_xor

if __name__=='__main__':
    ciphertext = unhexlify(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    key = highscore_xor(set(printable.encode()), ciphertext)
    print(chr(key))
    print(strxor_c(ciphertext, key))
