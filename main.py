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
from urllib.parse import urlencode


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
    path = urlparse(headers["(request-target)"]).path
    tail = headers["(request-target)"].split(path)[-1]
    headers["(request-target)"] = method + " " + path + tail

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


def make_headers(method, url, request_id, body, content_type="application/json", extra_headers={}):
    headers = {
        **extra_headers,
        "request-target": url,
        "Accept": "application/json",
        "Content-Type": content_type,  # Always the case?
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


redirect_url = "https://nu.nl"
psu_ip_address = "212.178.101.162"


def create_consent():
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

    # The URL that the user is redirected to after giving permission.
    url = "https://api.xs2a-sandbox.bngbank.nl/api/v1/consents"
    request_id = str(uuid.uuid4())

    headers = make_headers("post", url, request_id, body)

    r = requests.post(
        url,
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
    return r["consentId"]


def retrieve_access_token():
    access_code = input("Enter access code query string parameter from the previous step: ")

    body = {
        "client_id": "PSDNL-AUT-SANDBOX",
        "grant_type": "authorization_code",
        "code": access_code,
        "code_verifier": "12345",  # What is this?
        "state": "state12345",  # What is this?
        "redirect_uri": redirect_url
    }
    body = urlencode(body, doseq=False)

    url = "https://api.xs2a-sandbox.bngbank.nl/token"
    request_id = str(uuid.uuid4())

    headers = make_headers("post", url, request_id, body, content_type="application/x-www-form-urlencoded;charset=UTF-8")

    r = requests.post(
        url,
        data=body,
        headers=headers,
        cert=("xs2a_sandbox_bngbank_client_tls.cer", "xs2a_sandbox_bngbank_client_tls.key")
    )
    return r.json()["access_token"]


def retrieve_consent_details(consent_id, access_token):
    url = f"https://api.xs2a-sandbox.bngbank.nl/api/v1/consents/{consent_id}"
    request_id = str(uuid.uuid4())

    headers = make_headers("get", url, request_id, "", extra_headers={
        "Authorization": f"Bearer {access_token}"
    })

    r = requests.get(
        url,
        data="",
        headers=headers,
        cert=("xs2a_sandbox_bngbank_client_tls.cer", "xs2a_sandbox_bngbank_client_tls.key")
    )
    return r.json()


def read_available_accounts(consent_id, access_token):
    url = "https://api.xs2a-sandbox.bngbank.nl/api/v1/accounts?withBalance=true"
    request_id = str(uuid.uuid4())

    headers = make_headers("get", url, request_id, "", extra_headers={
        "Authorization": f"Bearer {access_token}",
        "Consent-ID": consent_id
    })

    r = requests.get(
        url,
        data="",
        headers=headers,
        cert=("xs2a_sandbox_bngbank_client_tls.cer", "xs2a_sandbox_bngbank_client_tls.key")
    )
    return r.json()


def read_transaction_list(consent_id, access_token, account_id):
    booking_status = "both"  # booked, pending or both
    date_from = "2018-01-01"
    with_balance = "false"

    url = f"https://api.xs2a-sandbox.bngbank.nl/api/v1/accounts/{account_id}/transactions?bookingStatus={booking_status}&dateFrom={date_from}&withBalance={with_balance}"
    request_id = str(uuid.uuid4())

    headers = make_headers("get", url, request_id, "", extra_headers={
        "Authorization": f"Bearer {access_token}",
        "Consent-ID": consent_id
    })

    r = requests.get(
        url,
        data="",
        headers=headers,
        cert=("xs2a_sandbox_bngbank_client_tls.cer", "xs2a_sandbox_bngbank_client_tls.key")
    )
    return r.json()


if __name__ == "__main__":
    consent_id = create_consent()
    access_token = retrieve_access_token()
    # consent_id = 'c63ee815-e405-4040-8b13-74a9b34ea668'
    # access_token = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3d3dy5ibmdiYW5rLm5sIiwic3ViIjoidGVzdHVzZXIwMSIsImF1ZCI6IlBTRE5MLUFVVC1TQU5EQk9YIiwiZXhwIjoxNjQwOTA1MjAwLCJuYmYiOjE2Mzg4MDg0ODcsImlhdCI6MTYzODgwODQ4NywianRpIjoiZWM1NDM1MGQtY2QyOS00YWY4LThhZTYtMzJhNzJmNWVjMmZiIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy91c2VyZGF0YSI6ImM2M2VlODE1LWU0MDUtNDA0MC04YjEzLTc0YTliMzRlYTY2OCJ9.fhuqiC3on4PYZsqtNPnJ8XENNKtsvn8lE7JNdb65uXyCJwTqUZlI5niwkvCsAAb5Izq6ERms0bN77Mkr9fUgyQ'
    consent_details = retrieve_consent_details(consent_id, access_token)
    available_accounts = read_available_accounts(consent_id, access_token)
    account_id = available_accounts["accounts"][0]["resourceId"]
    transactions = read_transaction_list(consent_id, access_token, account_id)
