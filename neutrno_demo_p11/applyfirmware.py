#!/usr/bin/env python3
import requests
import zipfile
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import os
#from Crypto.PublicKey import RSA

url = 'http://10.0.0.74:8000/polls/verify'
data = "test data"

firmware_file  = "/home/neutrno/code/signverify/neutrno_demo_p11/firmware"
#rsa_private_key = "/home/neutrno/code/signverify/poll/private_key_4096.pem"
signature_file = "/home/neutrno/code/signverify/neutrno_demo_p11/signature_data"

zipped_file = "/home/neutrno/code/signverify/neutrno_demo_p11/data.zip"
rsa_public_key_file = "/home/neutrno/code/signverify/neutrno_demo_p11/id_rsa_constructed.pub"
#f = open(rsa_private_key,'r')
#key = RSA.importKey(f.read())
#f.close()

#f = open(firmware_file , 'rb',)
#hash = SHA.new((f.read()))
#signer = PKCS1_v1_5.new(key)
#signature = signer.sign(hash)

#signature = key.sign(hash , ''
#f.close()
#print("signature : ")
#print(signature)
#print (signature[0])
#f = open(signature_file , 'wb')
#f.write(signature)
#f.close()

#f = open(firmware_file , 'a',)
#f.write("malware")
#f.close

f = zipfile.ZipFile(zipped_file , mode='w')
f.write(firmware_file, os.path.basename(firmware_file))
f.write(signature_file , os.path.basename(signature_file))
f.close()
file_to_be_sent = {'firmware' : open(zipped_file , 'rb'), 'pubkey': open(rsa_public_key_file, 'rb')}
response = requests.post(url, files=file_to_be_sent)
print(response.text)
