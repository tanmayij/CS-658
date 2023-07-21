import base64
import binascii
import json
import re
from binascii import unhexlify

import nacl
import nacl.secret
import nacl.utils
import requests
from nacl import pwhash, secret, utils

URL = "https://hash-browns.cs.uwaterloo.ca/api/psp/inbox"

headers = {
"accept": "application/json",
"Content-Type": "application/json"
}
params = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43"
}
#SENDING THE API REQUEST
resp = requests.post(URL, headers = headers ,data=json.dumps(params))
batman_response = str(resp.json())
print("batman response:",batman_response)

#LOCATE THE MESSAGE PART OF THE RESPONSE
message_where = batman_response.find("'msg': '")

#DECODE AND DEFINE SECRET BOX
batman_message_decoded = base64.b64decode(batman_response[(message_where+8):(len(batman_response)-3)])
print ("batman decoded:",batman_message_decoded)

#GET THE KEY AND SECRET BOX
preshared_password = b'costly appeal'
salt_hex = b'0d5667ec35b9415bab2d75532ae6380b'
opslimit = 2
memlimit = 67108864

#GET THE KEY
salt = unhexlify(salt_hex)
print ("salt",salt)
kdf = pwhash.argon2id.kdf
key = kdf(secret.SecretBox.KEY_SIZE, preshared_password, salt, opslimit, memlimit)
#key = "e0f7d22f74226435c2457407ed1c880709b4cdc11da0b28540b5e30d9848bb96"
#print ("Key in bytes:",(batman_message_decoded))
box = nacl.secret.SecretBox(key)

#DECRYPT TO PLAINTEXT
plaintext = box.decrypt(batman_message_decoded)
print("plaintext:",plaintext.decode('utf-8'))

if resp.status_code != 200:
    print('error: ' + str(resp.status_code))
else:
   # print('token: ' + str(tk))
    print('Success')