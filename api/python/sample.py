import requests
import time
import ecdsa
from hashlib import sha256

API_KEY = ""
API_SECRET = ""
ACCOUNT_ID = 0

time = int(time.time() * 1000000000)
payload = 'AUTH' + str(time)
signing_key = ecdsa.SigningKey.from_der(bytes.fromhex(API_SECRET))
rs = signing_key.sign(payload.encode('utf-8'), hashfunc=sha256)

HEADERS = {
    'X-AUTH-API-KEY': API_KEY,
    'X-AUTH-API-PAYLOAD': payload,
    'X-AUTH-API-SIGNATURE': rs.hex(),
    'X-AUTH-API-NONCE': str(time)
}

response = requests.get(url = 'http://api.demo.xena.io/trading/accounts/' + str(ACCOUNT_ID) + '/balance', headers = HEADERS)
print(str(response.status_code))
print(response.text)