import base64
import json
from base64 import b64decode

import nacl
import nacl.secret
import nacl.utils
import requests


#CONVERT SECRET KEY TO BINARY
hex_key = "e0f7d22f74226435c2457407ed1c880709b4cdc11da0b28540b5e30d9848bb96"
#binary_key32 = '{:032b}'.format(int(hex_key, 16))
box = nacl.secret.SecretBox(bytes.fromhex(hex_key))
#binary_key32 = binary_key[2:].zfill(32)
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

#MESSAGE
ciphertext = b"Test"
#GENERATE A RANDOM NONCE AND ENCRYPT
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
encrypted = box.encrypt(ciphertext, nonce)
#secret_box = nacl.crypto_secretbox_easy(ciphertext, nonce, binary_key)

#ENCRYPT MESSAGE
message = nonce + encrypted
print (message)
b1 = []
data = message
for char in data:
        mm = int(char.ecode('hex'), 16)
        b1.append(hex(mm))
print (b1)