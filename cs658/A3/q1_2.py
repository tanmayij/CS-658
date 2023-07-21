import base64
import json
import requests
import re

URL = "https://hash-browns.cs.uwaterloo.ca/api/plain/inbox"

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
print(batman_response)

#LOCATE THE MESSAGE PART OF THE RESPONSE
message_where = batman_response.find("'msg': '")
#print (message_where)

#DECODE AND PRINT MESAGE USING STRING MANIPULATIONS
batman_message_english = str(base64.b64decode(batman_response[(message_where+7):(len(batman_response)-3)]))
print (batman_message_english[2:len(batman_message_english)-1])
#print (str(batman_response))

if resp.status_code != 200:
    print('error: ' + str(resp.status_code))
else:
   # print('token: ' + str(tk))
    print('Success')
