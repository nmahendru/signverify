#!/usr/bin/env python3

#####
#Command to verify the contents of the public key generate from this program
#using openssl
#openssl rsa -text -inform PEM -pubin -in id_rsa_constructed.pub
#####
from Crypto.PublicKey.RSA import construct
f = open("modExponent",'r')
data = f.read()
data = data.split("#")
modulus = (data[0].split("="))[1]
exponent = (data[1].split("="))[1]
print ("modulus=" + modulus)
print ("exponent=" + exponent)
n = int(modulus, 16)
e = int(exponent, 16)
rsakey = construct((n, e))
exported_key = rsakey.exportKey()
f = open("id_rsa_constructed.pub" , 'wb')
f.write(exported_key)
f.close()
