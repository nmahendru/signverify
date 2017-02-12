#!/usr/bin/env python

from Crypto.Hash import SHA

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import construct
#e = int('10001' , 16)
#n = int(modulus, 16)
#rsakey = construct((n, long(e)))
#exported_key = rsakey.exportKey()
#f = open("id_rsa_constructed.pub" , 'wb')
#f.write(exported_key)
#f.close()
pub_key = open("id_rsa_constructed.pub", "rb").read()
rsakey = RSA.importKey(pub_key)
signer = PKCS1_v1_5.new(rsakey)
digest = SHA256.new()
f = open("signature_data", "rb")
signature = f.read()
f.close()
f = open("firmware" , "rb")
signature_input = f.read()
f.close()
digest.update(signature_input)
if signer.verify(digest, signature):
    print "verified"
else:
    print "not verified"
