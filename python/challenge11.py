from random import choice

import numpy as np
from pandas import DataFrame

from utilities import cbc_encrypt, ecb_encrypt, randomkey


def encryptor():
    key = randomkey()
    func = choice((cbc_encrypt, ecb_encrypt))
    prefix = np.ones(np.random.randint(5,10), np.uint8).tostring()
    suffix = np.ones(np.random.randint(5,10), np.uint8).tostring()
    func_out = lambda s: func(prefix + s + suffix, key)
    return func_out, func.__name__

def tester(crypt_fcn, blocksize):
    # have a test text long enough that there will be multiple blocks
    testtext = b'a'*100
    ciphertext = crypt_fcn(testtext)
    # chuck the first block as contaminated by the prefix
    start = ciphertext[:blocksize]
    blocka = ciphertext[blocksize:blocksize*2]
    blockb = ciphertext[blocksize*2:blocksize*3]
    if blocka == blockb:
        return 'ecb_encrypt'
    return 'cbc_encrypt'


if __name__=='__main__':
    encryptors = (encryptor() for i in range(1000))
    # build a confusion matrix for our tester to make sure that we're testing all
    # possible encryption schemes
    confusion_matrix = {'ecb_encrypt': {'ecb_encrypt': 0,
                                        'cbc_encrypt': 0},
                        'cbc_encrypt': {'ecb_encrypt': 0,
                                        'cbc_encrypt': 0}}
    for fcn, name in encryptors:
        confusion_matrix[name][tester(fcn, 16)] += 1

    # makes it look prettier
    print(DataFrame(confusion_matrix))


