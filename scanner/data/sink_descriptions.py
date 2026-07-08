"""
sink_descriptions.py
--------------------
Human-readable descriptions for data sinks.
"""

from typing import Dict, List

SINK_DESCRIPTIONS: Dict[str, str] = {
    "requests.post": "Transmits data through an HTTP POST request.",
    "requests.put": "Uploads data using HTTP PUT.",
    "requests.patch": "Uploads data using HTTP PATCH.",
    "requests.request": "Sends data through a generic HTTP request.",
    "socket.send": "Sends data through a network socket.",
    "socket.sendall": "Sends all data through a network socket.",
    "urllib.request.urlopen": "Sends data through a URL request.",
    "websocket.send": "Sends data through a WebSocket.",
    "ftplib.FTP.storbinary": "Uploads data to an FTP server.",
    "smtplib.SMTP.sendmail": "Transmits data via email.",
    "paramiko.SSHClient.exec_command": "Executes a remote SSH command.",
    "subprocess.run": "Executes a subprocess.",
    "os.system": "Executes system command.",
    "eval": "Evaluates Python expression.",
    "exec": "Executes Python code.",
    "unknown": "Unknown data destination.",
}


def get_sink_description(sink: str) -> str:
    """Get description for a sink type."""
    return SINK_DESCRIPTIONS.get(sink, f"Sink detected: {sink}")


def get_all_sink_types() -> List[str]:
    """Get all available sink types."""
    return list(SINK_DESCRIPTIONS.keys())


__all__ = [
    "SINK_DESCRIPTIONS",
    "get_sink_description",
    "get_all_sink_types",
]