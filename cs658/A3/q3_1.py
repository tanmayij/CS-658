import base64
import binascii
import json
from binascii import unhexlify

import nacl
import nacl.secret
import nacl.utils
import requests
from nacl import pwhash, secret, utils

URL = "https://hash-browns.cs.uwaterloo.ca/api/psp/send"

headers = {
"accept": "application/json",
"Content-Type": "application/json"
}
preshared_password = b'costly appeal'
salt_hex = b'0d5667ec35b9415bab2d75532ae6380b'
opslimit = 2
memlimit = 67108864

#GET THE KEY
salt = unhexlify(salt_hex)
print ("salt",salt)
kdf = pwhash.argon2id.kdf
key = kdf(secret.SecretBox.KEY_SIZE, preshared_password, salt, opslimit, memlimit)

#HERE WE ENCRYPT
box = nacl.secret.SecretBox(key)
text = b"Test"
#GENERATE A RANDOM NONCE AND ENCRYPT
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
encrypted = box.encrypt(text, nonce)
print ("encrypted:", encrypted)

#GET CIPHERTEXT
ctext = encrypted.ciphertext
print ("ctext:",ctext)
message = nonce + ctext
print ("message:",message)

base64_string = base64.b64encode(message)
base64_message = str(base64_string)
length = len(base64_message)
#print ("====")
print (base64_message[2:length-1])

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