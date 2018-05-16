from binascii import unhexlify, hexlify

from Crypto.Util.strxor import strxor

ciphertext = unhexlify(b'1c0111001f010100061a024b53535009181c')
keystring = unhexlify(b'686974207468652062756c6c277320657965')

plaintext = strxor(ciphertext, keystring)

answer = unhexlify(b'746865206b696420646f6e277420706c6179')

print(plaintext)
print(plaintext == answer)
