from base64 import b64decode
from string import printable

from utilities import ecb_encrypt, randomkey
from challenge11 import tester
printable = printable.encode()

key = randomkey()

unknown_string = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

def encryptor(plaintext):
    return ecb_encrypt(plaintext+unknown_string, key)

def get_blocksize(encryption):
    # calculate the block size
    testtext = b''
    len1 = len(encryptor(testtext))
    len2 = len1
    while len2 == len1:
        testtext += b'a'
        len2 = len(encryptor(testtext))
    blocksize = len2 - len1
    return blocksize, len1 // blocksize

def crack(encryption, blocksize, nblocks):
    plaintext = b'' # this is updated every time a new block is decrypted
    for i in range(nblocks):
        thisblock = b''
        for j in range(blocksize-1, -1, -1):
            pref = b'a'*j
            unknown = encryptor(pref)[i*blocksize:(i+1)*blocksize]
            for c in printable:
                test_ecb = encryptor(pref+plaintext+thisblock+chr(c).encode())
                if test_ecb[i*blocksize:(i+1)*blocksize] == unknown:
                    thisblock += chr(c).encode()
                    break
        plaintext += thisblock
    return plaintext
            

# confirm that this is an ecb encryption scheme
if __name__=='__main__':

    blocksize, nblocks = get_blocksize(encryptor)
    assert tester(encryptor, blocksize) == 'ecb_encrypt'

    print(crack(encryptor, blocksize, nblocks))


