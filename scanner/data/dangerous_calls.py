"""
dangerous_calls.py
------------------
Dangerous call definitions for dangerous_api.py.
Each entry: (severity, category, reason)
"""

from typing import Dict, Tuple

DANGEROUS_CALLS: Dict[str, Tuple[str, str, str]] = {
    # (severity, category, reason)
    
    # =====================================
    # Code Execution
    # =====================================
    "eval": ("HIGH", "Code Execution", "Executes arbitrary Python expressions from a string."),
    "exec": ("HIGH", "Code Execution", "Executes arbitrary Python code from a string."),
    "compile": ("HIGH", "Code Execution", "Compiles and can execute arbitrary code strings."),
    "__import__": ("HIGH", "Code Execution", "Dynamic import — can load arbitrary modules at runtime."),
    "os.system": ("HIGH", "Code Execution", "Runs a shell command — direct OS command execution."),
    "os.popen": ("HIGH", "Code Execution", "Opens a pipe to a shell command."),
    "os.execv": ("HIGH", "Code Execution", "Replaces the current process with another program."),
    "os.execve": ("HIGH", "Code Execution", "execve variant — same risk."),
    "os.spawn": ("HIGH", "Code Execution", "Spawns a new process."),
    "subprocess.call": ("HIGH", "Code Execution", "Executes a system command."),
    "subprocess.run": ("HIGH", "Code Execution", "Executes a system command (modern API)."),
    "subprocess.Popen": ("HIGH", "Code Execution", "Opens a subprocess — full shell access."),
    "subprocess.check_output": ("HIGH", "Code Execution", "Runs a command and captures its output."),
    "importlib.import_module": ("HIGH", "Code Execution", "Dynamically imports a module by name."),
    "ctypes.cdll.LoadLibrary": ("HIGH", "Code Execution", "Loads a native shared library — can call arbitrary C code."),
    "ctypes.windll": ("HIGH", "Code Execution", "Loads Windows DLLs directly."),
    
    # =====================================
    # Network
    # =====================================
    "socket.socket": ("HIGH", "Network", "Creates a raw network socket."),
    "socket.connect": ("HIGH", "Network", "Opens a network connection."),
    "requests.get": ("MEDIUM", "Network", "HTTP GET — can retrieve remote resources or C2 instructions."),
    "requests.post": ("HIGH", "Network", "HTTP POST — primary vector for exfiltrating data."),
    "requests.put": ("HIGH", "Network", "HTTP PUT — can upload data to a remote server."),
    "requests.delete": ("MEDIUM", "Network", "HTTP DELETE — can trigger remote actions."),
    "urllib.request.urlopen": ("MEDIUM", "Network", "Opens a URL — can fetch or post data externally."),
    "urllib.request.urlretrieve": ("MEDIUM", "Network", "Downloads a file from a URL."),
    
    # =====================================
    # Obfuscation
    # =====================================
    "base64.b64encode": ("MEDIUM", "Obfuscation", "Base64 encoding — often used to hide data before exfiltration."),
    "base64.b64decode": ("MEDIUM", "Obfuscation", "Base64 decoding — often used to unpack hidden payloads."),
    "base64.encodebytes": ("MEDIUM", "Obfuscation", "Alternate base64 encoder — same risk."),
    "zlib.compress": ("MEDIUM", "Obfuscation", "Compression — can be used to pack obfuscated payloads."),
    "zlib.decompress": ("MEDIUM", "Obfuscation", "Decompression — can be used to unpack obfuscated payloads."),
    "gzip.compress": ("MEDIUM", "Obfuscation", "Compression — same dual-use as zlib."),
    "gzip.decompress": ("MEDIUM", "Obfuscation", "Decompression — same dual-use as zlib."),
    
    # =====================================
    # Unsafe Deserialization
    # =====================================
    "pickle.loads": ("HIGH", "Unsafe Deserial.", "Deserializes untrusted data — can execute arbitrary code."),
    "pickle.load": ("HIGH", "Unsafe Deserial.", "Same as pickle.loads — file-based deserialization."),
    "marshal.loads": ("HIGH", "Unsafe Deserial.", "Deserializes bytecode — can run arbitrary Python code."),
    
    # =====================================
    # Credential Theft / Reconnaissance
    # =====================================
    "os.getenv": ("LOW", "Reconnaissance", "Reads environment variables — can harvest secrets from env."),
    "os.environ": ("MEDIUM", "Reconnaissance", "Access to all environment variables."),
    "getpass.getpass": ("HIGH", "Credential Theft", "Prompts for and captures a password."),
    "os.getlogin": ("LOW", "Reconnaissance", "Retrieves the current user's login name."),
    "platform.system": ("LOW", "Reconnaissance", "Retrieves the system/OS name."),
    "platform.node": ("LOW", "Reconnaissance", "Retrieves the network hostname."),
    "socket.gethostname": ("LOW", "Reconnaissance", "Retrieves the local hostname."),
    
    # =====================================
    # Persistence
    # =====================================
    "winreg.OpenKey": ("HIGH", "Persistence", "Opens a Windows Registry key."),
    "winreg.SetValueEx": ("HIGH", "Persistence", "Writes a value to the Registry — persistence mechanism."),
    "winreg.CreateKey": ("HIGH", "Persistence", "Creates a Windows Registry key."),
    
    # =====================================
    # Destructive / Anti-Forensics
    # =====================================
    "shutil.rmtree": ("HIGH", "Destructive", "Recursively deletes a directory — anti-forensic potential."),
    "os.remove": ("MEDIUM", "File Access", "Deletes a file."),
    "os.unlink": ("MEDIUM", "File Access", "Same as os.remove."),
    "os.rmdir": ("MEDIUM", "File Access", "Deletes an empty directory."),
    
    # =====================================
    # File Access
    # =====================================
    "open": ("LOW", "File Access", "Opens a file — low risk alone, but combined with network = exfiltration."),
}

# ==========================================
# EXPORTS
# ==========================================

__all__ = ["DANGEROUS_CALLS"]