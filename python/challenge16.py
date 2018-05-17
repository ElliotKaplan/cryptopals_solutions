from Crypto.Util.strxor import strxor_c, strxor

from utilities import *

key = randomkey()

def encrypt_userdata(data):
    stopchars = (b';', b'=')
    for c in stopchars:
        data = data.replace(c, b'')
    data = b''.join((b"comment1=cooking%20MCs;userdata=",
                     data,
                     b";comment2=%20like%20a%20pound%20of%20bacon"))
    return cbc_encrypt(data, key)

def is_admin(cookie):
    data = cbc_decrypt(cookie, key)
    vals = data.split(b';')
    return b'admin=true' in vals


blocksize, nblocks = get_blocksize(encrypt_userdata)
# make two blocks of 'a's

target_string = pkcs_7(b';admin=true;', blocksize)
valid_ciphertext = encrypt_userdata(b'a'*blocksize*2)

# get the string that is our target xored with our dummy block
mapstring = strxor_c(target_string, ord(b'a'))
# corrupt the first block of dummy text to modify the second
valid_ciphertext = list(to_blocks(valid_ciphertext, blocksize))
valid_ciphertext[2] = strxor(valid_ciphertext[2], mapstring)
corrupted = b''.join(valid_ciphertext)

print(is_admin(corrupted))
