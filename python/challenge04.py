from binascii import unhexlify
from collections import Counter
from string import ascii_letters, printable

from Crypto.Util.strxor import strxor_c

from challenge03 import highscore_xor

keyspace = set(range(1, 0x100))
most_common = set(b'etaoin shrdlu')

high_score = 0
with open('../input_files/4.txt') as fobj:
    for lineno, line in enumerate(fobj):
        line = unhexlify(line.strip())
        key = highscore_xor(keyspace, line)
        if key is None:
            continue
        line = strxor_c(line, key)
        count = Counter(line.lower())
        score = sum(count[c] for c in most_common)
        if score > high_score:
            trueline = line
            truekey = key
            truelineno = lineno
            high_score = score
print(truelineno, chr(truekey))
print(trueline)



