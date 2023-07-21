import base64
import json

import nacl
import nacl.secret
import nacl.utils
import requests
import binascii
from binascii import unhexlify


#CONVERT SECRET KEY TO BINARY AND BOX IT
hex_key = "e0f7d22f74226435c2457407ed1c880709b4cdc11da0b28540b5e30d9848bb96"
print ("Key in bytes:",unhexlify(hex_key))
box = nacl.secret.SecretBox(unhexlify(hex_key))

#MESSAGE
text = b"Test"
#GENERATE A RANDOM NONCE AND ENCRYPT
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
encrypted = box.encrypt(text, nonce)
print ("encrypted:", encrypted)

#GET CIPHERTEXT
ctext = encrypted.ciphertext
print (ctext)
#MAKE MESSAGE
message = nonce + ctext
print ("message:",message)

URL = "https://hash-browns.cs.uwaterloo.ca/api/psk/send"

headers = {
"accept": "application/json",
"Content-Type": "application/json"
}
#message = "Hello, World!"
base64_string = base64.b64encode(message)
base64_message = str(base64_string)
length = len(base64_message)
#print ("====")
#print (base64_message)

params = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43",
"recipient": "Batman", "msg" : "" + base64_message[2:length-1]+ ""
}

resp = requests.post(URL, headers = headers ,data=json.dumps(params))
#tk = json.loads(resp.text)['token']

if resp.status_code != 200:
    print('error: ' + str(resp.status_code))
else:
   # print('token: ' + str(tk))
    print('Success')
