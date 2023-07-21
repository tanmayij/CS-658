import base64
import binascii
import json
import re
from binascii import unhexlify

import nacl
import nacl.secret
import nacl.utils
import requests
import nacl.encoding
import nacl.hash
from nacl.public import PrivateKey, Box, PublicKey
import pysodium

URL = "https://hash-browns.cs.uwaterloo.ca/api/pke/get-key"

headers = {
"accept": "application/json",
"Content-Type": "application/json"
}
params = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43",
"user" : "Batman"
}
#SENDING THE API REQUEST
resp = requests.post(URL, headers = headers ,data=json.dumps(params))
batman_response = str(resp.json())
#print("batman response:",batman_response)

#LOCATE THE MESSAGE PART OF THE RESPONSE
message_where = batman_response.find("'pubkey': '")

#DECODE THE PUBLIC KEY
batman_key_decoded = base64.b64decode(batman_response[(message_where+11):(len(batman_response)-2)])
#print ("batman decoded:",batman_message_decoded)

#HASH THE DECODED KEY
HASHER = nacl.hash.blake2b
#message = b'Banana'
digest = HASHER(batman_key_decoded, encoder=nacl.encoding.HexEncoder)

print(nacl.encoding.HexEncoder.encode(batman_key_decoded))
print(digest)


if resp.status_code != 200:
    print('error: ' + str(resp.status_code))
else:
   # print('token: ' + str(tk))
    print('Success Response 1')

#PART 2
url_2 = "https://hash-browns.cs.uwaterloo.ca/api/pke/set-key"

headers_2 = {
"accept": "application/json",
"Content-Type": "application/json"
}
pk, sk = nacl.bindings.crypto_kx_keypair()
print (pk, sk)
public_key = str(base64.b64encode(pk))
len2 = len(public_key)
params_2 = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43",
"pubkey" : "" + public_key[2:len2-1] + ""
}
#SENDING THE API REQUEST 2
resp2 = requests.post(url_2, headers = headers_2 ,data=json.dumps(params_2))
response2_str = str(resp2.json())

if resp2.status_code != 200:
    print('error: ' + str(resp2.status_code))
else:
   # print('token: ' + str(tk))
    print('Success Response 2')

url_3 = "https://hash-browns.cs.uwaterloo.ca/api/pke/send"

# pk, sk = nacl.bindings.crypto_kx_keypair()
# print (pk, sk)

msg = b'Banana'
nonce = nacl.utils.random(Box.NONCE_SIZE)

enc_msg = nacl.bindings.crypto_box(msg, nonce, batman_key_decoded, sk)
ctext = base64.b64encode(nonce + enc_msg)
#print (ctext)

sending_this = str(ctext)
len3 = len(sending_this)
params_3 = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43",
"recipient": "Batman", "msg" : "" + sending_this[2:len3-1]+ ""
}
#SENDING THE API REQUEST 3
resp3 = requests.post(url_3, headers = headers_2 ,data=json.dumps(params_3))
response3_str = str(resp3.json())

if resp3.status_code != 200:
    print('error: ' + str(resp3.status_code))
else:
   # print('token: ' + str(tk))
    print('Success Response 3')


#PART 3
URL_4 = "https://hash-browns.cs.uwaterloo.ca/api/pke/inbox"

params_4 = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43"
}

resp4 = requests.post(URL_4, headers = headers_2 ,data=json.dumps(params_4))
response4_str = str(resp4.json())
print (response4_str)

#LOCATE THE MESSAGE PART OF THE RESPONSE
msg4_where = response4_str.find("'msg': '")

#DECODE AND DEFINE SECRET BOX
message_frm_batman = base64.b64decode(response4_str[(msg4_where+8):(len(response4_str)-3)])
print ("message decoded:",type(message_frm_batman))

#DECRYPT THIS MESSAGE
boxDecrypt = Box(PrivateKey(sk), PublicKey(batman_key_decoded))
plaintext = boxDecrypt.decrypt(message_frm_batman)
print (plaintext)
if resp4.status_code != 200:
    print('error: ' + str(resp4.status_code))
else:
   # print('token: ' + str(tk))
    print('Success Response 4')