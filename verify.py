#!/usr/bin/env python3
import base64, ecdsa, json, qrtools, urllib.request
from hashlib import sha256

def add_b64_padding(s):
    return s + (-len(s)%4)*"="

def read_qr(image="myCovidPass-2.png"):
    covidPass = qrtools.QR(filename=image)
    covidPass.decode()
    return covidPass.data_to_string().decode("utf-8-sig")

PROD_COVID_KEYS = "https://covid-status.service.nhsx.nhs.uk/pubkeys/keys.json" 

def getCovidSigningKeys(covidKeysURL = PROD_COVID_KEYS):
    with urllib.request.urlopen(covidKeysURL) as url:
        return json.loads(url.read().decode())

def parse_payload(p):
    payload = base64.b64decode(add_b64_padding(p))
    expiry =  [payload[n:n+2].decode("utf-8") for n in range(1, 11, 2)]
    name = payload[11:].decode("utf-8")
    return (expiry, name)

header, payload, signature = read_qr().split(".")
pubKeys = getCovidSigningKeys()
ecPubKey = [i['publicKey'] for i in pubKeys if i['kid'] == add_b64_padding(header)][0]
byteData = (header + "." + payload).encode("utf-16le")
sigBytes = base64.b64decode(add_b64_padding(signature), "-_")

verifier = ecdsa.VerifyingKey.from_pem(ecPubKey, hashfunc=sha256)
if verifier.verify(sigBytes,byteData):
    print("VERIFIED")
    expiry, name = parse_payload(payload)
    print('CovidPass for {0}, valid until 20{1}-{2}-{3} {4}:{5} GMT'.format(name, *expiry))


