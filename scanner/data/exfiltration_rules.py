"""
exfiltration_rules.py
---------------------
Chain rules for exfiltration_tracer.py.
Defines attack chain patterns based on source, sink, and transforms.
"""

from typing import List, Dict, Any, Set

# ==========================================
# SOURCE CATEGORIES
# ==========================================

FILE_SOURCES: Set[str] = {"file_read"}
ENV_SOURCES: Set[str] = {"env_var", "credential"}
ALL_SOURCES: Set[str] = {"file_read", "env_var", "credential", "user_input", "network_recv"}

# ==========================================
# NETWORK SINKS
# ==========================================

NETWORK_SINKS: Set[str] = {
    "requests.post",
    "requests.put",
    "requests.patch",
    "socket.send",
    "socket.sendall",
    "ftplib.FTP.storbinary",
    "smtplib.SMTP.sendmail",
}

# ==========================================
# CODE EXECUTION SINKS
# ==========================================

EXEC_SINKS: Set[str] = {
    "eval",
    "exec",
    "compile",
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
}

# ==========================================
# CHAIN RULES
# ==========================================

CHAIN_RULES: List[Dict[str, Any]] = [
    # =====================================
    # Data Exfiltration
    # =====================================
    {
        "name": "Data Exfiltration",
        "sources": {"file_read"},
        "sinks": NETWORK_SINKS,
        "confidence": "HIGH",
        "description": "File data read and transmitted to a remote server.",
    },
    
    # =====================================
    # Credential Exfiltration
    # =====================================
    {
        "name": "Credential Exfiltration",
        "sources": {"env_var", "credential"},
        "sinks": NETWORK_SINKS,
        "confidence": "CRITICAL",
        "description": "Credentials/env secrets harvested and sent over the network.",
    },
    
    # =====================================
    # Encoded Exfiltration
    # =====================================
    {
        "name": "Encoded Exfiltration",
        "sources": ALL_SOURCES,
        "sinks": NETWORK_SINKS,
        "requires_transform": True,
        "confidence": "HIGH",
        "description": "Data encoded/transformed before transmission — hiding content from inspection.",
    },
    
    # =====================================
    # Remote Code Execution via Tainted Input
    # =====================================
    {
        "name": "Remote Code Execution via Tainted Input",
        "sources": {"user_input", "network_recv"},
        "sinks": EXEC_SINKS,
        "confidence": "CRITICAL",
        "description": "User/network input flows into eval()/exec() — attacker-controlled code execution.",
    },
    
    # =====================================
    # Stealthy Exfiltration (with anti-forensics)
    # =====================================
    {
        "name": "Stealthy Data Exfiltration",
        "sources": {"file_read"},
        "sinks": NETWORK_SINKS,
        "requires_transform": True,
        "confidence": "CRITICAL",
        "description": "File data encoded/transformed and transmitted — combined with anti-forensic behavior.",
    },
]

# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "CHAIN_RULES",
    "NETWORK_SINKS",
    "EXEC_SINKS",
    "FILE_SOURCES",
    "ENV_SOURCES",
    "ALL_SOURCES",
]