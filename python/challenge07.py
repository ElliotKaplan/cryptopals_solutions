from base64 import b64decode

from utilities import ecb_decrypt

with open('../input_files/7.txt') as fi:
    ciphertext = b64decode(fi.read())
    
# print(ecb_decrypt(ciphertext, b'YELLOW SUBMARINE'))
it = ecb_decrypt(ciphertext, b'YELLOW SUBMARINE', return_iter=True)
print(b''.join(it))
