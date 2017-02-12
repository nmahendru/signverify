from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import zipfile

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
# Create your views here.


def index(request):
    return HttpResponse("Hello, world. You're at the polls index.");
@csrf_exempt
def verify(request):
    #This function will be used to return the response of the verification of the file that is received.
    if request.method == 'GET':
      print ("get request received")
      print ("The path of the request is this " + request.path)

    elif request.method == 'POST':
      print("post request received")
      print ("The path of the request is this " + request.path)
      print (request.FILES)
      firmware = request.FILES["file"]
      #time to verify the signature
      content = firmware.read()
      #print (content)
      zipped_file = "/home/nitin/code/signverify/poll/data_received.zip"
      directory_to_extract = "/home/nitin/code/signverify/poll/test1"
      f = open(zipped_file , 'wb')
      f.write(content)
      f.close()
      f = zipfile.ZipFile(zipped_file , mode='r')
      return_value = f.extractall(directory_to_extract)
      f.close()
      #print(return_value)
      public_key = "/home/nitin/code/signverify/poll/public_key_4096.pub"
      key = RSA.importKey(open(public_key).read())
      f = open(directory_to_extract + "/test_firmware" , 'rb')
      h = SHA.new(f.read())
      f.close()
      f = open(directory_to_extract + "/signature_file" , 'rb')
      signature = f.read()
      #print (signature)
      f.close()
      verifier = PKCS1_v1_5.new(key)
      if verifier.verify(h, signature):
       print("successfully verified")
       return HttpResponse("signature verification succeeded")
      else:
       print("could not verify signature")
       return HttpResponse("signature verification failed")
