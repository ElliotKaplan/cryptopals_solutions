from binascii import unhexlify
from collections import Counter
from string import ascii_letters, printable

from Crypto.Util.strxor import strxor_c

ascii_letters = ascii_letters.encode()
printable = printable.encode()

most_common = set(b'etaoin shrdlu')

ciphertext = unhexlify(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')

# any character in the cipher text cannot be the key, there would be null
# characters in the plaintext in this case. 
keyspace = set(range(1, 0x100)).difference(set(ciphertext))

# choose the high score by having the most characters in the most common
# character set
highscore = 0
for key in keyspace:
    decipher = strxor_c(ciphertext, key)
    counter = Counter(decipher.lower())
    score = sum(counter[k] for k in most_common)
    if score > highscore:
        highscore = score
        truekey = key

print(chr(truekey))
print(strxor_c(ciphertext, truekey))



    
