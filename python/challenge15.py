from utilities import is_pkcs_7

teststrs = (b"ICE ICE BABY\x04\x04\x04\x04",
            b"ICE ICE BABY\x05\x05\x05\x05",
            b"ICE ICE BABY\x01\x02\x03\x04")

for i, teststr in enumerate(teststrs):
    try:
        is_pkcs_7(teststr)
        print(i, '\t', 'is valid pkcs_7')
    except ValueError:
        print(i, '\t', 'is NOT valid pkcs_7')
