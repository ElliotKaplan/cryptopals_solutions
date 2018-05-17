from base64 import b64decode

from utilities import cbc_decrypt, cbc_encrypt

with open('../input_files/10.txt') as fi:
    ciphertext = b64decode(
        ''.join((line.strip() for line in fi)).encode())

key = b'YELLOW SUBMARINE'

plain = cbc_decrypt(ciphertext, key)

print(plain)
