
from utilities import randomkey, ecb_encrypt, ecb_decrypt, pkcs_7

key = randomkey()

def cookie_parser(string_in):
    # convert a cookie string to a cookie dictionary
    return dict(el.split(b'=') for el in string_in.split(b'&'))

def to_cookie(dictionary):
    # convert a cookie dictionary to a cookie string
    return b'&'.join(map(b'='.join, dictionary.items()))

def profile_for(email):
    for stopchar in (b'&', b'='):
        email = email.replace(stopchar, b'')
    cookie = {b'email': email, b'uid': b'10', b'role': b'user'}
    return ecb_encrypt(to_cookie(cookie), key)

def profile_from(cipher):
    # convert ciphertext to a cookie
    cookiestring = ecb_decrypt(cipher, key)
    # get rid of padding bytes
    if cookiestring[-1] in range(1,16):
        cookiestring = cookiestring[:-cookiestring[-1]]
    return cookie_parser(cookiestring)

# find the block size
email = b'a@a'
len1 = len(profile_for(email))
len2 = len1
while len2 == len1:
    email += b'a'
    len2 = len(profile_for(email))
blocksize = len2-len1
# create the encrypted block for admin+padding
admin = pkcs_7(b'admin', blocksize)
adminblock = profile_for(email+admin)[blocksize:blocksize*2]
# create an encrypted string with 'user' removed
email = email + 3*b'a'
profile = profile_for(email)[:-blocksize] + adminblock
print(profile_from(profile))



