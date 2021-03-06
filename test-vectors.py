#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import aes_siv
import binascii

def unhexlify(s):
    return binascii.unhexlify(''.join(s.strip().split()))

def hexlify(d):
    return ' '.join([ binascii.hexlify(d[i:i+4]) for i in range(0, len(d), 4) ])

def test():
    aead = aes_siv.AES_SIV()

    print("Key:  ", hexlify(key), "(%d bytes)" % len(key))
    print("AD:   ", hexlify(ad), "(%d bytes)" % len(ad))
    print("Nonce:", hexlify(nonce), "(%d bytes)" % len(nonce))
    print("Plain:", hexlify(plaintext), "(%d bytes)" % len(plaintext))
    print()

    ciphertext = aead.encrypt(key, nonce, plaintext, ad)

    print()
    print("Out:   ", hexlify(ciphertext), "(%d bytes)" % len(ciphertext))
    print()

print("Test data based on A.2 in https://tools.ietf.org/html/rfc5297")
print()

print("AD2 has been dropped")
print()

key = unhexlify('''7f7e7d7c 7b7a7978 77767574 73727170
                   40414243 44454647 48494a4b 4c4d4e4f''')

ad = unhexlify('''00112233 44556677 8899aabb ccddeeff
                  deaddada deaddada ffeeddcc bbaa9988
                  77665544 33221100''')
nonce = unhexlify('''09f91102 9d74e35b d84156c5 635688c0''')

plaintext = unhexlify('''74686973 20697320 736f6d65 20706c61
                         696e7465 78742074 6f20656e 63727970
                         74207573 696e6720 5349562d 414553''')

test()

# Test data from A.2 with zero length plaintext

key = unhexlify('''7f7e7d7c 7b7a7978 77767574 73727170
                   40414243 44454647 48494a4b 4c4d4e4f''')

ad = unhexlify('''00112233 44556677 8899aabb ccddeeff
                  deaddada deaddada ffeeddcc bbaa9988
                  77665544 33221100''')
nonce = unhexlify('''09f91102 9d74e35b d84156c5 635688c0''')

plaintext = unhexlify('''''')

print("AD2 has been dropped, zero length plaintext")
print()

test()
