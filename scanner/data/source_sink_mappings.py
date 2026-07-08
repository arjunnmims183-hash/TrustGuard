"""
source_sink_mappings.py
-----------------------
Source and sink mappings for source_sink_tracker.py.
"""

from typing import Dict, Set, Callable, Optional

# ==========================================
# NETWORK SINKS
# ==========================================

NETWORK_SINKS: Set[str] = {
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.request",
    "socket.send",
    "socket.sendall",
    "ftplib.FTP.storbinary",
    "smtplib.SMTP.sendmail",
    "urllib.request.urlopen",
    "websocket.send",
    "paramiko.SSHClient.exec_command",
}

# ==========================================
# TRANSFORM FUNCTIONS
# ==========================================

TRANSFORM_FUNCTIONS: Dict[str, str] = {
    # (call_name: transform_name)
    "base64.b64encode": "base64_encode",
    "base64.encodebytes": "base64_encode",
    "zlib.compress": "zlib_compress",
    "gzip.compress": "gzip_compress",
    "binascii.hexlify": "hexlify",
    "json.dumps": "json_serialize",
    "pickle.dumps": "serialize",
    "str.encode": "encode",
}

# ==========================================
# SOURCE DETECTION
# ==========================================

def detect_source(call_name: str) -> Optional[str]:
    """
    Detect if a call is a data source and return the source type.
    """
    source_map = {
        "open": "file_read",
        "os.getenv": "env_var",
        "os.environ.get": "env_var",
        "getpass.getpass": "credential",
        "input": "user_input",
        "requests.get": "network_recv",
        "socket.recv": "network_recv",
    }
    return source_map.get(call_name)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "NETWORK_SINKS",
    "TRANSFORM_FUNCTIONS",
    "detect_source",
]