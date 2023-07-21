from nacl.encoding import Base64Encoder
from nacl.signing import SigningKey
# Generate a new random signing key
signing_key = SigningKey.generate()
print (type(signing_key))
# Sign a message with the signing key
signed_b64 = signing_key.sign(b"Attack at Dawn", encoder=Base64Encoder)
# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key
print (type(verify_key))
# Serialize the verify key to send it to a third party
verify_key_b64 = verify_key.encode(encoder=Base64Encoder)\\




    with open("secretkey.txt", "r") as outfile:
     secret_key = outfile.read()
     print (bytes(secret_key, 'utf-8'))
secret_key_decoded = base64.b64decode(secret_key)
print("decoded secret key:",secret_key_decoded)
#print (secret_key)
with open("keypair.txt", "r") as outfile:
     id_sk = eval(outfile.read())

# Sign a message with the signing key
#signed = nacl.bindings.crypto_sign(bytes(secret_key_decoded), id_sk)
#signed = SigningKey(secret_key_decoded).sign(b"I just want hugs", encoder=Base64Encoder)
