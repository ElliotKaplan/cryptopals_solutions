from string import printable
from collections import Counter
import struct

import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor, strxor_c

most_common = set(b'etaoin shrdlu')
unprintable = set(range(0x100)).difference(set(printable.encode()))

def u32_bool(num):
    return np.fromiter(((num & 2**i) // 2**i
                        for i in range(31, -1, -1)), np.bool)
def bool_u32(boolarr):
    return (boolarr * np.power(2, np.arange(31, -1, -1))).sum()

def randomkey(size=16):
    return np.uint8(np.random.randint(0x100, size=size)).tostring()

def highscore_xor(keyspace, ciphertext):
    # returns the key with the highest number of characters in the most_common
    # set, and no unprintable characters

    # any character in the ciphertext is excluded as null byte generating
    keyspace = keyspace.difference(set(ciphertext))
    highscore = 0
    for key in keyspace:
        decipher = strxor_c(ciphertext, key)
        # skip if there are any unprintable characters
        if any(c in unprintable for c in decipher):
            continue
        count = Counter(decipher.lower())
        score = sum(count[k] for k in most_common)
        if score > highscore:
            highscore = score
            truekey = key
    # if no key actually works, return None
    try:
        return truekey
    except NameError:
        return None

def repeating_xor(key, plaintext):
    # computes the xor of the plaintext with a repeating key
    keylen = len(key)
    split_text = (plaintext[i::keylen] for i in range(keylen))
    xor_split = tuple(strxor_c(txt, k) for txt, k in zip(split_text, key))
    # have to encode the text becaue python3 is puts the characters into
    # unicode strings
    xor_text = ''.join(''.join(map(chr, t)) for t in zip(*xor_split)).encode()
    # if the key doesn't match the text length exactly, add in the last
    # characters from 
    remainder = len(plaintext) % keylen
    xor_text += ''.join(chr(s[-1]) for s in xor_split[:remainder]).encode()
    return xor_text

def hamming_distance(string1, string2):
    # hamming distance is defined as the count of different bits, use the xored
    # of the two strings to calculate this
    xorstring = strxor(string1, string2)
    xorarr = np.fromstring(xorstring, np.uint8)
    # compute the number of 1 bits in the xorstring
    dist = sum(((xorarr & i) // i).sum()
               for i in np.power(2, np.arange(8)))
    return dist

def get_blocksize(encryption):
    # calculate the block size
    testtext = b''
    len1 = len(encryption(testtext))
    len2 = len1
    while len2 == len1:
        testtext += b'a'
        len2 = len(encryption(testtext))
    blocksize = len2 - len1
    return blocksize, len1 // blocksize

def pkcs_7(string_in, blocksize=16):
    # pad a string to valid pkcs_7
    padlen = blocksize - (len(string_in) % blocksize)
    if padlen == blocksize:
        return string_in
    return string_in + (np.zeros(padlen, np.uint8)+padlen).tostring()

def is_pkcs_7(string_in, blocksize=16):
    # confirm that a string is properly padded
    padlen = string_in[-1]
    if any(c != padlen for c in string_in[-padlen:]):
        raise ValueError("Invalid pkcs_7")
    return True


def to_blocks(text, blocksize):
    # splits a character array into individual blocks. returns an iterator over blocks
    c_arr = np.fromstring(text, np.uint8).reshape(-1, blocksize)
    yield from (c.tostring() for c in c_arr)

def ecb_decrypt(ciphertext, key, initial_vec=None, return_iter=False):
    # decrypt using AES-128-ECB. returns a generator of plaintext blocks
    crypto = AES.new(key, AES.MODE_ECB)
    bsize = crypto.block_size
    ciphertext = pkcs_7(ciphertext, bsize)
    decryption = map(crypto.decrypt, to_blocks(ciphertext, bsize))
    if return_iter:
        return decryption
    return b''.join(decryption)

def ecb_encrypt(plaintext, key, initial_vec=None, return_iter=False):
    # encrypt using AES-128-ECB. Returns an generator of ciphertext blocks
    crypto = AES.new(key, AES.MODE_ECB)
    bsize = crypto.block_size
    plaintext = pkcs_7(plaintext, bsize)
    encryption = map(crypto.encrypt, to_blocks(plaintext, bsize))
    if return_iter:
        return encryption
    return b''.join(encryption)

def cbc_decrypt(ciphertext, key, initial_vec=None, return_iter=False):
    # decrypt using AES-128-CBC. returns a generator of plaintext blocks
    crypto = AES.new(key, AES.MODE_ECB)
    bsize = crypto.block_size
    if initial_vec is None:
        initial_vec = np.zeros(bsize, np.uint8).tostring()
    ciphertext = pkcs_7(ciphertext)
    # iterator for decrypted text
    def decryption():
        xor_vec = initial_vec
        for block in to_blocks(ciphertext, bsize):
            plain = strxor(xor_vec, crypto.decrypt(block))
            xor_vec = block
            yield plain
    if return_iter:
        return decryption()
    return b''.join(decryption())

def cbc_encrypt(plaintext, key, initial_vec=None, return_iter=False):
    # decrypt using AES-128-CBC. returns a generator of plaintext blocks
    crypto = AES.new(key, AES.MODE_ECB)
    bsize = crypto.block_size
    if initial_vec is None:
        initial_vec = np.zeros(bsize, np.uint8).tostring()
    plaintext = pkcs_7(plaintext)
    # iterator for encrypted text
    def encryption():
        xor_vec = initial_vec
        for block in to_blocks(plaintext, bsize):
            cipher = crypto.encrypt(strxor(xor_vec, block))
            xor_vec = cipher
            yield cipher
    if return_iter:
        return encryption()
    return b''.join(encryption())

def cbc_validate(*args):
    plaintext = cbc_decrypt(*args)
    try:
        return is_pkcs_7(plaintext)
    except:
        return False

def ctr_cipher(text_in, key, nonce):
    crypto = AES.new(key, AES.MODE_ECB)
    bsize = crypto.block_size
    # generator of cipher keys
    def keystream(nblocks):
        for i in range(nblocks):
            raw = struct.pack('<QQ', nonce, i)
            yield crypto.encrypt(raw)
    nblocks = (len(text_in) // bsize) + 1
    ks = b''.join(keystream(nblocks))
    return strxor(text_in, ks[:len(text_in)])
    
    
