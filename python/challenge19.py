from base64 import b64decode
from functools import partial

import numpy as np
from Crypto.Util.strxor import strxor

from utilities import ctr_cipher, randomkey, highscore_xor

key = randomkey()
cipher = partial(ctr_cipher, key=key, nonce=0)

with open('../input_files/19.txt') as fi:
    plaintexts = map(b64decode, fi.read().split('\n'))
    # eliminate empty lines
    plaintexts = list(filter(lambda x: x, plaintexts))

ciphertexts = list(map(cipher, plaintexts))
# find the longest text
keylen = max(map(len, ciphertexts))


# guess the keystring from letter frequency

# keyguess = b'\x00' * keylen
# keyspaces = list(k if k else set(range(0x100)) for k in keyguess)

# keyguess = np.fromstring(keyguess, np.uint8)
# for i, ks in enumerate(keyspaces):
#     string_in = np.fromiter((c[i] for c in ciphertexts if i < len(c)),
#                             np.uint8).tostring()
#     keyguess[i] = highscore_xor(ks, string_in)
# keyguess = keyguess.tostring()

# for i, text in enumerate(ciphertexts):
#     print(i, strxor(keyguess[:len(text)], text))

# compute the keystring from successively longer plaintexts

# keystring = strxor(ciphertexts[25],
#                    b'This other his helper and friend')

# keystring = strxor(ciphertexts[27],
#                    b'He might have won fame in the end.')

# keystring = strxor(ciphertexts[4],
#                    b'I have passed with a nod of the head')

keystring = strxor(ciphertexts[37],
                   b'He, too, has been changed in his turn,')

for i, text in enumerate(ciphertexts):
    last = min(len(keystring), len(text))
    print(i, strxor(keystring[:last], text[:last]))
