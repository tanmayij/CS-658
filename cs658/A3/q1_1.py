import base64
import json
import requests

URL = "https://hash-browns.cs.uwaterloo.ca/api/plain/send"

headers = {
"accept": "application/json",
"Content-Type": "application/json"
}
message = "Hello, World!"
m = message.encode('latin-1')
print(m)
base64_string = base64.b64encode(m)
base64_message = str(base64_string)
length = len(base64_message)
print (base64_message)
print(base64_message[2:length-1])
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