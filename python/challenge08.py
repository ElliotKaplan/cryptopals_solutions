from binascii import unhexlify
from itertools import combinations

import numpy as np
from utilities import ecb_decrypt

with open('../input_files/8.txt') as fi:
    ciphertext = [unhexlify(line.strip()) for line in fi]

# find the line with repeated 16 character blocks
for lineno, line in enumerate(ciphertext):
    blocks = list(np.fromstring(line, np.uint8).reshape(-1, 16))
    blocks = [b.tostring() for b in blocks]
    # if any blocks are repeated, the line was probably ecb encrypted
    for a, b in combinations(blocks, 2):
        if a == b:
            print(lineno)
            break
