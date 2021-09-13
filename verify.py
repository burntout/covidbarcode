#!/usr/bin/env python3
from hashlib import sha256
from datetime import datetime
import base64
import urllib.request
import json
import ecdsa
import qrtools

def add_b64_padding(s):
    return s + (-len(s)%4)*"="

def read_qr(image="myCovidPass.png"):
    covid_pass = qrtools.QR(filename=image)
    covid_pass.decode()
    return covid_pass.data_to_string().decode("utf-8-sig")

PROD_COVID_KEYS = "https://covid-status.service.nhsx.nhs.uk/pubkeys/keys.json"

def get_covid_signing_keys(covid_keys_url = PROD_COVID_KEYS):
    try:
        with urllib.request.urlopen(covid_keys_url) as url:
            pub_keys = json.loads(url.read().decode())
    except:
        with open('cache/keys.json') as f:
            pub_keys = json.load(f)
    return pub_keys

def parse_payload(p):
    payload = base64.b64decode(add_b64_padding(p))
    expiry =  [payload[n:n+2].decode("utf-8") for n in range(1, 11, 2)]
    name = payload[11:].decode("utf-8")
    return (expiry, name)

def verify_signature(header, payload, signature):
    pub_keys = get_covid_signing_keys()
    ec_pub_key = [i['publicKey'] for i in pub_keys if i['kid'] == header][0]
    byte_data = (header + "." + payload).encode("utf-16le")
    sig_bytes = base64.b64decode(add_b64_padding(signature), "-_")
    verifier = ecdsa.VerifyingKey.from_pem(ec_pub_key, hashfunc=sha256)
    return verifier.verify(sig_bytes,byte_data)

def check_date(expiry):
    current_time = datetime.utcnow()
    exp_year = int("20" + expiry[0])
    exp_month = int(expiry[1])
    exp_day = int(expiry[2])
    exp_hour = int(expiry[3])
    exp_min = int(expiry[4])
    exp_date = datetime(exp_year,exp_month,exp_day, exp_hour, exp_min)
    return exp_date >= current_time

def main():
    valid_qr = False
    valid_sig = False
    valid_payload = False
    valid_date = False

    try:
        qr_data = read_qr().split(".")
        if len(qr_data) == 3:
            valid_qr = True
            header, payload, signature = qr_data
    except:
        valid_qr = False

    if not valid_qr:
        print("Invalid QR code")
        exit()

    try:
        valid_sig = verify_signature(header, payload, signature)
        if valid_sig:
            expiry, name = parse_payload(payload)
    except:
        valid_sig = False

    if not valid_sig:
        print("Invalid signature")
        exit()

    try:
        valid_date = check_date(expiry)
    except:
        valid_date = False

    if valid_date:
        print('CovidPass for {0}, valid until 20{1}-{2}-{3} {4}:{5} GMT'.format(name, *expiry))
    else:
        print("Expired pass")
        exit()

if __name__ == "__main__":
    main()
