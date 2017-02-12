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

url = 'http://127.0.0.1:8000/polls/verify'
data = "test data"

firmware_file  = "/home/nitin/code/signverify/poll/test_firmware"
rsa_private_key = "/home/nitin/code/signverify/poll/private_key_4096.pem"
signature_file = "/home/nitin/code/signverify/poll/signature_file"

zipped_file = "/home/nitin/code/signverify/poll/data.zip"
f = open(rsa_private_key,'r')
key = RSA.importKey(f.read())
f.close()

f = open(firmware_file , 'rb',)
hash = SHA.new((f.read()))
signer = PKCS1_v1_5.new(key)
signature = signer.sign(hash)

#signature = key.sign(hash , ''
f.close()
#print("signature : ")
#print(signature)
#print (signature[0])
f = open(signature_file , 'wb')
f.write(signature)
f.close()

#f = open(firmware_file , 'a',)
#f.write("malware")
#f.close

f = zipfile.ZipFile(zipped_file , mode='w')
f.write(firmware_file, os.path.basename(firmware_file))
f.write(signature_file , os.path.basename(signature_file))
f.close()
file_to_be_sent = {'file' : open(zipped_file , 'rb')}
response = requests.post(url, files=file_to_be_sent)
print(response)
