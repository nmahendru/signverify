#!/usr/bin/env python

#####
#Command to verify the contents of the public key generate from this program
#using openssl
#openssl rsa -text -inform PEM -pubin -in id_rsa_constructed.pub
#####
from Crypto.PublicKey.RSA import construct
e = int('10001' , 16)
modulus = (
'cebae729ff2f9bbbe0fa'
'a26b4f0aa78ba044d4f2'
'b04d6cfdae3e5a21da1b'
'9c7d1608319015ee69a2'
'544a4ab33a3df442a577'
'0d7d8159b6d77d37f13d'
'be5273d8b380de3951a3'
'00ce576a1b8bb067c840'
'f74e377f5ca1212e8c9b'
'9ab8ce43de8f7029c188'
'dc837a62e2ef351518ee'
'0fb5fd7fbe71b026ed05'
'd9905f934b11e53feac0'
'e1c523d9d09d3d1c4516'
'f42c6565e5fcf261e02e'
'7cd6cc71b58a410cfeb0'
'6420774a9e2726332bfd'
'34c26a15bdca060c92ea'
'6050b490caa95fb44a02'
'006af42bb192b538d9e8'
'3420118fab07224a8917'
'01df79be8f7ba1f8a9fc'
'5d00e8c80054d505bfa5'
'829ba10ddf43f8fd2874'
'8bdf383cf21ba9ee2e6c'
'7e17a524f6d1'
)
n = int(modulus, 16)
rsakey = construct((n, long(e)))
exported_key = rsakey.exportKey()
f = open("id_rsa_constructed.pub" , 'wb')
f.write(exported_key)
f.close()
