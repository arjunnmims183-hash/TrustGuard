"""
dangerous_imports.py
--------------------
Risky import definitions for dangerous_api.py.
Each entry: (severity, category, reason)
"""

from typing import Dict, Tuple

RISKY_IMPORTS: Dict[str, Tuple[str, str, str]] = {
    # (severity, category, reason)
    
    # =====================================
    # Code Execution
    # =====================================
    "subprocess": ("HIGH", "Code Execution", "Can execute arbitrary system commands."),
    "importlib": ("HIGH", "Code Execution", "Allows dynamic module loading — can load malicious code at runtime."),
    "ctypes": ("HIGH", "Code Execution", "Direct access to C libraries — can call arbitrary native code."),
    "cffi": ("HIGH", "Code Execution", "C Foreign Function Interface — similar risk to ctypes."),
    "pty": ("HIGH", "Code Execution", "Provides pseudo-terminal — can spawn interactive shells."),
    
    # =====================================
    # System Access
    # =====================================
    "os": ("MEDIUM", "System Access", "Provides access to OS-level operations (files, processes, env)."),
    "sys": ("LOW", "System Access", "Can modify Python runtime, path, and exit behavior."),
    
    # =====================================
    # Network
    # =====================================
    "socket": ("HIGH", "Network", "Enables raw TCP/UDP network communication."),
    "requests": ("MEDIUM", "Network", "HTTP client — can send data to external servers."),
    "urllib": ("MEDIUM", "Network", "Another HTTP client — can fetch or post data externally."),
    "http": ("MEDIUM", "Network", "Low-level HTTP communication."),
    "ftplib": ("HIGH", "Network", "FTP client — can upload files to remote servers."),
    "smtplib": ("HIGH", "Network", "SMTP client — can send emails (data exfiltration vector)."),
    "paramiko": ("HIGH", "Network", "SSH client — can connect to remote machines and execute commands."),
    
    # =====================================
    # Obfuscation
    # =====================================
    "base64": ("MEDIUM", "Obfuscation", "Commonly used to encode/obfuscate payloads or exfiltrate data."),
    "zlib": ("MEDIUM", "Obfuscation", "Compression — can be used to pack/unpack obfuscated payloads."),
    "gzip": ("MEDIUM", "Obfuscation", "Compression — same dual-use as zlib."),
    
    # =====================================
    # Unsafe Deserialization
    # =====================================
    "pickle": ("HIGH", "Unsafe Deserial.", "Deserializing untrusted pickle data allows arbitrary code execution."),
    "marshal": ("HIGH", "Unsafe Deserial.", "Similar to pickle — can execute code on deserialization."),
    "shelve": ("HIGH", "Unsafe Deserial.", "Built on pickle — same deserialization risk."),
    
    # =====================================
    # File Access
    # =====================================
    "shutil": ("MEDIUM", "File Access", "File operations including copy, move, delete of entire trees."),
    "tempfile": ("LOW", "File Access", "Creates temporary files — sometimes used to stage payloads."),
    "glob": ("LOW", "File Access", "File discovery — can be used to map out filesystem contents."),
    "fnmatch": ("LOW", "File Access", "File pattern matching — similar to glob."),
    
    # =====================================
    # Persistence
    # =====================================
    "winreg": ("HIGH", "Persistence", "Windows Registry access — classic persistence mechanism."),
    "sched": ("MEDIUM", "Persistence", "Task scheduler — can be used to create time-triggered logic bombs."),
    
    # =====================================
    # Execution
    # =====================================
    "threading": ("LOW", "Execution", "Multi-threading — can be used to hide background activity."),
    "multiprocessing": ("LOW", "Execution", "Multi-process spawning — can obscure malicious child processes."),
    "signal": ("MEDIUM", "Execution", "Signal handling — can intercept and suppress shutdown signals."),
    
    # =====================================
    # Reconnaissance
    # =====================================
    "platform": ("LOW", "Reconnaissance", "System fingerprinting — OS, hostname, architecture."),
    "psutil": ("MEDIUM", "Reconnaissance", "Process/system monitoring — can enumerate running processes and connections."),
    "grp": ("MEDIUM", "Reconnaissance", "Reads Unix group database — system enumeration."),
    
    # =====================================
    # Credential Theft
    # =====================================
    "getpass": ("HIGH", "Credential Theft", "Reads passwords from the terminal — strong exfiltration signal."),
    "keyring": ("HIGH", "Credential Theft", "Reads stored system credentials."),
    "pwd": ("HIGH", "Credential Theft", "Reads Unix password database entries."),
    
    # =====================================
    # Crypto
    # =====================================
    "cryptography": ("MEDIUM", "Crypto", "Legitimate use is common, but also used to encrypt/decrypt payloads."),
    "Crypto": ("MEDIUM", "Crypto", "PyCryptodome — same dual-use as cryptography."),
    "hashlib": ("LOW", "Crypto", "Hashing library — low risk but sometimes used to hash stolen data."),
}

# ==========================================
# EXPORTS
# ==========================================

__all__ = ["RISKY_IMPORTS"]