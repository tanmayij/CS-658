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

URL = "https://hash-browns.cs.uwaterloo.ca/api/prekey/set-identity-key"

headers = {
"accept": "application/json",
"Content-Type": "application/json"
}

id_vk, id_sk = nacl.bindings.crypto_sign_keypair()
print ("vk:", id_vk)
print ("sk:", id_sk)

batPublicKey_hex = str(base64.b64encode(bytes(id_vk)))
length = len(batPublicKey_hex)

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

#GET PREKEY NOW 
#pk, sk = nacl.bindings.crypto_kx_keypair()
secret_key = nacl.public.PrivateKey.generate()
public_key = secret_key.public_key
signed_prekey = str(base64.b64encode(nacl.bindings.crypto_sign(bytes(public_key), id_sk)))
len_prekey = len(signed_prekey)

url_2 = "https://hash-browns.cs.uwaterloo.ca/api/prekey/set-signed-prekey"

params_2 = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43",
"pubkey" : "" + signed_prekey[2:len_prekey-1] + ""
}
resp2 = requests.post(url_2, headers = headers ,data=json.dumps(params_2))

if resp2.status_code != 200:
    print('error: ' + str(resp2.status_code))
else:
   # print('token: ' + str(tk))
    print('Success response 2')

#part 2

url_3 = "https://hash-browns.cs.uwaterloo.ca/api/prekey/get-identity-key"
params_3 = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43", 
"user": "Batman"
}

#SENDING THE API REQUEST FOR PREKEY
resp3 = requests.post(url_3, headers = headers ,data=json.dumps(params_3))
batman_response = str(resp3.json())
print("batman response:",batman_response)

pubkey_where = batman_response.find("'pubkey': '")
#print (pubkey_where)
#DECODE AND DEFINE SECRET BOX
#print (batman_response[(pubkey_where+11):(len(batman_response)-2)])
batman_id_vk = base64.b64decode(batman_response[(pubkey_where+11):(len(batman_response)-2)])

signed_key_url = "https://hash-browns.cs.uwaterloo.ca/api/prekey/get-signed-prekey"
params_4 = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43", 
"user": "Batman"
}

resp4 = requests.post(signed_key_url, headers = headers ,data=json.dumps(params_4))
url4_resp = str(resp4.json())
print (url4_resp)
signed_prekey_where = url4_resp.find("'pubkey': '")
print (url4_resp[(signed_prekey_where+11):(len(url4_resp)-2)])
batman_signed_prekey = base64.b64decode(url4_resp[(signed_prekey_where+11):(len(url4_resp)-2)])

obtained_pk = nacl.bindings.crypto_sign_open(batman_signed_prekey, batman_id_vk)
print (obtained_pk)

plaintext = b'hoot hoot'
nonce = nacl.utils.random(Box.NONCE_SIZE)
encrypted = nacl.bindings.crypto_box(plaintext, nonce, obtained_pk, bytes(secret_key))

ctext = str(base64.b64encode(nonce + encrypted))
ctext_len = len(ctext)
print (ctext)
print ("ctext:",ctext[2:ctext_len-1])

send_msg_url = "https://hash-browns.cs.uwaterloo.ca/api/prekey/send"

params_5 = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43",
"recipient": "Batman",
"msg" : "" + ctext[2:ctext_len-1] + ""
}

resp5 = requests.post(send_msg_url, headers = headers ,data=json.dumps(params_5))

if resp5.status_code != 200:
    print('error: ' + str(resp5.status_code))
else:
   # print('token: ' + str(tk))
    print('Success response 5')

#PART 3
url6= "https://hash-browns.cs.uwaterloo.ca/api/prekey/inbox"

params_6 = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43",
"user": "Batman",
}

#SENDING THE API REQUEST
resp4 = requests.post(url6, headers = headers ,data=json.dumps(params_6))
message_fom_batman = str(resp4.json())
print("batman response:",message_fom_batman)

msg_where = message_fom_batman.find("'msg': '")

message_decoded = base64.b64decode(message_fom_batman[(msg_where+8):(len(message_fom_batman)-2)])
boxx = Box(secret_key, PublicKey(bytes(obtained_pk)))
plaintext = boxx.decrypt(message_decoded)
print(plaintext.decode('utf-8'))

