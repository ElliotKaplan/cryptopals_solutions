from base64 import b64decode
from string import printable

import numpy as np

from utilities import ecb_encrypt, randomkey
from challenge11 import tester
from challenge12 import get_blocksize
printable = printable.encode()

key = randomkey()
prefix = np.random.randint(0x100, size=np.random.randint(5, 10))
prefix = np.uint8(prefix).tostring()

unknown_string = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

def encryptor(plaintext):
    return ecb_encrypt(prefix+plaintext+unknown_string, key)

def get_prefix_complement(encryptor, bsize):
    for prefcomp in range(bsize):
        testtext = b'a'*(2*bsize + prefcomp)
        crypted = encryptor(testtext)
        if crypted[bsize:2*bsize] == crypted[bsize*2:bsize*3]:
            break
    # have the complement of the prefix len
    return prefcomp


def crack(encryption, prefix_complement, blocksize, nblocks):
    plaintext = b'' # this is updated every time a new block is decrypted
    for i in range(1, nblocks+1):
        thisblock = b''
        for j in range(blocksize-1, -1, -1):
            pref = b'a'*(j + prefix_complement)
            unknown = encryptor(pref)[i*blocksize:(i+1)*blocksize]
            for c in printable:
                test_ecb = encryptor(pref+plaintext+thisblock+chr(c).encode())
                if test_ecb[i*blocksize:(i+1)*blocksize] == unknown:
                    thisblock += chr(c).encode()
                    break
        plaintext += thisblock
    return plaintext

        
if __name__=='__main__':
    blocksize, nblocks = get_blocksize(encryptor)
    assert tester(encryptor, blocksize) == 'ecb_encrypt'
    prefix_complement = get_prefix_complement(encryptor, blocksize)
    print(crack(encryptor, prefix_complement, blocksize, nblocks))
