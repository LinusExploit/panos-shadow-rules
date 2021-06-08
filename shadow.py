import sys
import requests
import json
import xmltodict
# a script that is used to parse shadowed policies in Panorama
requests.packages.urllib3.disable_warnings()


# generate an api key and store it locally
# URL to Generate the API
URL = 'https://192.168.1.66/api/?type=keygen&user=admin&password=Asd_12345'
s1 = requests.session()
s1.verify = False
r1 = s1.get(URL)

# convert response into json
k1 = xmltodict.parse(r1.text)
k2 = json.dumps(k1)

k3 = json.loads(k2)
key = k3['response']['result']['key']
#print(key)

# URL for warnings
warnings_stream = '<show><shadow-warning><count><device-serial>015351000065266</device-serial></count></shadow-warning></show>'
url2 = 'https://192.168.1.66/api/?'
#print(url2)

r2 = s1.get(url2, params= {'type':'op','key':key, 'cmd': warnings_stream})
#print(r2.text)


# convert response into json
k1 = xmltodict.parse(r2.text)
k2 = json.dumps(k1)

k3 = json.loads(k2)

rules = []
#counter = len(k3['response']['result']['shadow-warnings-count']['entry']['entry'])
#print(k3['response']['result']['shadow-warnings-count']['entry']['entry'])
for i in k3['response']['result']['shadow-warnings-count']['entry']['entry']:
   rules.append({'name':i['@name'], 'uuid':i['@uuid'], 'count': i['#text']})

for rule in rules:
    print(rule['name'])
    print("This Rule shadows the following Rules")
    url3 = 'https://192.168.1.66/api/?'
    cmd = '<show><shadow-warning><warning-message><device-group>NGFW-MAIN</device-group><device-serial>015351000065266</device-serial><uuid>{}</uuid></warning-message></shadow-warning></show>'
    r3 = s1.get(url3, params= {'type':'op','key':key, 'cmd': cmd.format(rule['uuid'])})

    k1 = xmltodict.parse(r3.text)
    k2 = json.dumps(k1)
    k3 = json.loads(k2)

    shadowed_by = k3['response']['result']['warning-msg']['member']
    print(shadowed_by)
