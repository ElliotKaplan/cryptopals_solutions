from base64 import b64encode
from binascii import unhexlify

hexstring = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
asciistring = unhexlify(hexstring)
b64string = b64encode(asciistring)
answer = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
print(asciistring)
print(b64string == answer)
