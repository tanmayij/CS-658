import base64
import binascii
import json
import sys
import re
from binascii import unhexlify
from nacl.encoding import Base64Encoder

import nacl
import nacl.secret
import nacl.utils
import requests
from nacl.public import PrivateKey, Box

URL = "https://hash-browns.cs.uwaterloo.ca/api/signed/set-key"

headers = {
"accept": "application/json",
"Content-Type": "application/json"
}
params = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43"
}

# Generate private key, which must be kept secret
bat_secret = PrivateKey.generate()
#print (sys.getsizeof(bat_secret))
id_vk, id_sk = nacl.bindings.crypto_sign_keypair()
print ("vk:", id_vk)
print ("sk:", id_sk)
# bat_Secret_str = str(bat_secret.encode(encoder=Base64Encoder))
# print (bat_Secret_str)
with open("secretkey.txt", "w") as outfile:
    outfile.write(str(base64.b64encode(id_sk)))

#GENERATE PUBLIC KEY AND ENCODE, SEND API
bat_public = bat_secret.public_key
with open("publickey.txt", "w") as outfile:
    outfile.write(str(bat_public))
batPublicKey_hex = str(base64.b64encode(bytes(id_vk)))
length = len(batPublicKey_hex)
print (batPublicKey_hex)

params = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43",
"pubkey" : "" + batPublicKey_hex[2:length-1] + ""
}

resp = requests.post(URL, headers = headers ,data=json.dumps(params))

if resp.status_code != 200:
    print('error: ' + str(resp.status_code))
else:
   # print('token: ' + str(tk))
    print('Success')