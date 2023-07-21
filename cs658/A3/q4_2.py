import base64
import binascii
import json
import re
from binascii import unhexlify
from nacl.encoding import Base64Encoder

import nacl
import nacl.secret
import nacl.utils
import requests
from nacl.signing import SigningKey
from nacl.signing import VerifyKey

URL = "https://hash-browns.cs.uwaterloo.ca/api/signed/send"

headers = {
"accept": "application/json",
"Content-Type": "application/json"
}
params = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43"
}
#RETRIEVE THE SECRET KEY SAVED FROM PART 1
with open("secretkey.txt", "r") as outfile:
     secret_key = eval(outfile.read())
print ("secretkey:",secret_key)

#DECODE THE SECRET KEY
secret_key_decoded = base64.b64decode(secret_key)
print(secret_key_decoded)

# SIGN A MESSAGE WITH SK USING CRYPTO_SIGN
message = b'Can I borrow your batmobile tomorrow'
signed = nacl.bindings.crypto_sign(message, secret_key_decoded)
signed_str = str(base64.b64encode(signed))
length = len(signed_str)

params = {
"api_token" : "7703c19fad316470f4c4f6cae49f51692073af1ac811385030fd217e701ead43",
"recipient": "Batman", "msg" : "" + signed_str[2:length-1]+ ""
}

resp = requests.post(URL, headers = headers ,data=json.dumps(params))

if resp.status_code != 200:
    print('error: ' + str(resp.status_code))
else:
   # print('token: ' + str(tk))
    print('Success')