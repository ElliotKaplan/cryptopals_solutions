from base64 import b64decode
from utilities import ctr_cipher

txt = b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')

key = 'YELLOW SUBMARINE'
nonce = 0

print(ctr_cipher(txt, key, nonce))
