from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import zipfile

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import subprocess
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
      #print("post request received")
      #print ("The path of the request is this " + request.path)
      #print (request.FILES)
      firmware = request.FILES["firmware"]
      publickey = request.FILES["pubkey"]
      #time to verify the signature
      f_content = firmware.read()
      p_content = publickey.read()
      public_key = "/home/neutrno/code/signverify/poll/mysite/polls/id_rsa.pub"
      f = open( public_key , 'wb')
      f.write(p_content)
      f.close()
      #print (content)
      zipped_file = "/home/neutrno/code/signverify/poll/mysite/polls/data_received.zip"
      directory_to_extract = "/home/neutrno/code/signverify/poll/mysite/polls/test1"
      f = open(zipped_file , 'wb')
      f.write(f_content)
      f.close()
      f = zipfile.ZipFile(zipped_file , mode='r')
      return_value = f.extractall(directory_to_extract)
      f.close()
      #print(return_value)
      key = RSA.importKey(open(public_key).read())
      f = open(directory_to_extract + "/firmware" , 'rb')
      h = SHA256.new(f.read())
      f.close()
      f = open(directory_to_extract + "/signature_data" , 'rb')
      signature = f.read()
      #print (signature)
      f.close()
      verifier = PKCS1_v1_5.new(key)
      if verifier.verify(h, signature):
       print(" ")
       print(" ")
       print(" ")
       print(" ")

       print("successfully verified the signature on the new firmware received.")
       print("the firmware file has the below stats")
       subprocess.run(["ls" , "-al" , directory_to_extract + "/firmware"])
       print(" ")
       print(" ")
       return HttpResponse("SIGNATURE VERIFICATION SUCCEDED. FIRMWARE WILL BE APPLIED ON THE IOT DEVICE")
      else:
       print(" ")
       print(" ")
       print(" ")
       print(" ")

       print("could not verify signature the signature on the firmware received")
       print("Cannot used this on the IOT DEVICE")
       print(" ")
       print(" ")

       return HttpResponse("SIGNATURE VERIFICATION FAILED. FIRMWARE CANNOT BE USED ON THE IOT DEVICE")
