from base64 import b64decode
from string import printable

from utilities import ecb_encrypt, randomkey
from challenge11 import tester
printable = printable.encode()

key = randomkey()

unknown_string = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

def encryptor(plaintext):
    return ecb_encrypt(plaintext+unknown_string, key)

# calculate the block size
testtext = b''
len1 = len(encryptor(testtext))
len2 = len1
while len2 == len1:
    testtext += b'a'
    len2 = len(encryptor(testtext))
blocksize = len2 - len1
# confirm that this is an ecb encryption scheme
assert tester(encryptor, blocksize) == 'ecb_encrypt'

nblocks = len1 // blocksize
plaintext = b'' # this is updated every time a new block is decrypted

for i in range(nblocks):
    known = b'' # this is the known characters in this block 
    for j in range(blocksize-1, -1, -1):
        pref = b'a'*j
        unknown = encryptor(pref)[i*blocksize:(i+1)*blocksize]
        for c in printable:
            test_ecb = encryptor(pref+plaintext+known+chr(c).encode())
            if test_ecb[i*blocksize:(i+1)*blocksize] == unknown:
                known += chr(c).encode()
                break
    plaintext += known

print(plaintext)

    
