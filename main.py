import json
import uuid
import requests
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime
import hashlib
import base64
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from urllib.parse import urlparse


# The URL that the user is redirected to after giving permission.
redirect_url = "https://nu.nl"
consent_url = "https://api.xs2a-sandbox.bngbank.nl/api/v1/consents"
request_id = str(uuid.uuid4())
psu_ip_address = "212.178.101.162"


def get_current_rfc_1123_date():
    now = datetime.now()
    stamp = mktime(now.timetuple())
    return format_date_time(stamp)


def get_digest(body):
    hash = hashlib.sha256()
    body = body.replace(" ", "")  # To equalize input with Valentin's code.
    hash.update(body.encode("utf-8"))
    digest_in_bytes = hash.digest()
    # Verified that this is the same string as in Valentin's code if the input is equal.
    digest_in_base64 = base64.b64encode(digest_in_bytes)
    return "SHA-256=" + digest_in_base64.decode("utf-8")


def get_signature(method, headers):
    signature_header_names = [
        "request-target", "Date", "Digest", "X-Request-ID"
    ]
    headers = {k: v for k, v in headers.items() if k in signature_header_names}
    headers = {"(request-target)" if k == "request-target" else k.lower(): v
               for k, v in headers.items()}
    headers["(request-target)"] = method + " " + urlparse(headers["(request-target)"]).path
    signing_string = "\n".join([k + ": " + v for k, v in headers.items()])
    signature_headers = " ".join(headers.keys())

    digest = SHA256.new()
    digest.update(bytes(signing_string, encoding="utf-8"))

    with open("xs2a_sandbox_bngbank_client_signing.key", "r") as file:
        private_key = RSA.importKey(file.read())

    signer = PKCS1_v1_5.new(private_key)
    signature = base64.b64encode(signer.sign(digest))

    return ",".join([
        "keyId=\"SN=00E8B54055D929413F,CA=CN=xs2a_sandbox_bngbank_client_signing, E=klantenservice@bngbank.nl, O=BNG Bank, OU=API XS2A Sandbox, C=NL, S=South-Holland, L=The Hague, OID.2.5.4.97=PSDNL-AUT-SANDBOX\"",
        "algorithm=\"sha256RSA\"",
        "headers=\"" + signature_headers + "\"",
        "signature=\"" + signature.decode("utf-8") + "\""
    ])


def get_certificate():
    with open("xs2a_sandbox_bngbank_client_signing.cer", "r") as file:
        data = file.read().replace("\n", "")
    return data


def make_headers(method, url, request_id, body):
    headers = {
        "request-target": url,
        "Accept": "application/json",
        "Content-Type": "application/json",  # Always the case?
        "Date": get_current_rfc_1123_date(),
        "Digest": get_digest(body),
        "X-Request-ID": request_id,
        "PSU-IP-Address": psu_ip_address
    }
    return {
        **headers,
        "Signature": get_signature(method, headers),
        "TPP-Signature-Certificate": get_certificate()
    }


body = {
    "access": {
        "accounts": None,
        "balances": None,
        "transactions": None,
        "availableAccounts": None,
        "availableAccountsWithBalances": None,
        "allPsd2": "allAccounts"
    },
    "combinedServiceIndicator": False,
    "recurringIndicator": True,
    "validUntil": "2021-12-31",
    "frequencyPerDay": 4
}

body = json.dumps(body).replace(" ", "")

headers = make_headers("post", consent_url, request_id, body)

r = requests.post(
    consent_url,
    data=body,
    headers=headers,
    cert=("xs2a_sandbox_bngbank_client_tls.cer", "xs2a_sandbox_bngbank_client_tls.key")
).json()

print(
    "".join([
        "https://api.xs2a-sandbox.bngbank.nl/authorise?response_type=code&",
        "client_id=PSDNL-AUT-SANDBOX&",
        "state=state12345&",
        "scope=" + 'AIS:' + r["consentId"] + "&",
        "code_challenge=12345&",
        "code_challenge_method=Plain&",
        "redirect_uri=" + redirect_url,
    ])
)
