from itertools import combinations
from base64 import b64decode

import numpy as np

from utilities import hamming_distance, highscore_xor, repeating_xor

keysizes = list(range(2, 40))

with open('../input_files/6.txt') as fi:
    ciphertext = b64decode(fi.read())

# find the most probable key lengths by averaging the edit distances for 4 keylen sized chunks
hamdists = np.zeros(40)
samples = ((ciphertext[0:ks], ciphertext[ks:ks*2],
            ciphertext[ks*2:ks*3], ciphertext[ks*3:ks*4])
           for ks in keysizes)
# six possible permutations
for (ks, s) in zip(keysizes, samples):
    hamdists[ks] = sum(hamming_distance(*c) / ks
                       for c in combinations(s, 2)) / 6
# ignore zero and 1 as possible keylens
keylen = hamdists.argsort()[2]

# get the most probable key for each slice. Have separate keyspaces in case the
# most probable key doesn't actually work and the calculation needs to be
# rerun.
keyspaces = [set(range(0x100)) for _ in range(keylen)]
keys = (highscore_xor(k, ciphertext[i::keylen])
        for i, k in enumerate(keyspaces))
keystring = ''.join(map(chr, keys)).encode()

print(repeating_xor(keystring, ciphertext).decode())
