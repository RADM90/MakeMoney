import os
import jwt
import uuid
import hashlib
from urllib.parse import urlencode

import requests

access_key = os.environ['UPBIT_OPEN_API_ACCESS_KEY']
secret_key = os.environ['UPBIT_OPEN_API_SECRET_KEY']
server_url = os.environ['UPBIT_OPEN_API_SERVER_URL']

query = {
    'state': 'done',
}
query_string = urlencode(query)

uuids = [
    '9ca023a5-851b-4fec-9f0a-48cd83c2eaae',
    #...
]
uuids_query_string = '&'.join(["uuids[]={}".format(uuid) for uuid in uuids])

query['uuids[]'] = uuids
query_string = "{0}&{1}".format(query_string, uuids_query_string).encode()

m = hashlib.sha512()
m.update(query_string)
query_hash = m.hexdigest()

payload = {
    'access_key': access_key,
    'nonce': str(uuid.uuid4()),
    'query_hash': query_hash,
    'query_hash_alg': 'SHA512',
}

jwt_token = jwt.encode(payload, secret_key).decode('utf-8')
authorize_token = 'Bearer {}'.format(jwt_token)
headers = {"Authorization": authorize_token}

res = requests.get(server_url + "/v1/orders", params=query, headers=headers)

print(res.json())