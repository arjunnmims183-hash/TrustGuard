"""
dangerous_api.py
----------------
Detects risky/dangerous function calls and imports in a parsed Python file.

Works in two layers:
  1. Import-level  - flags risky modules that were imported at all
  2. Call-level    - flags specific dangerous function/method calls

Each finding includes:
    category    - what type of risk (code execution, network, obfuscation, etc.)
    name        - the import or call name
    lineno      - where it appears
    severity    - LOW / MEDIUM / HIGH
    reason      - plain-English explanation
"""

import ast
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Risk definitions
# ---------------------------------------------------------------------------

# Risky imports: module name -> (severity, category, reason)
RISKY_IMPORTS = {
    "subprocess":   ("HIGH",   "Code Execution",  "Can execute arbitrary system commands."),
    "os":           ("MEDIUM", "System Access",   "Provides access to OS-level operations (files, processes, env)."),
    "sys":          ("LOW",    "System Access",   "Can modify Python runtime, path, and exit behavior."),
    "socket":       ("HIGH",   "Network",         "Enables raw TCP/UDP network communication."),
    "requests":     ("MEDIUM", "Network",         "HTTP client — can send data to external servers."),
    "urllib":       ("MEDIUM", "Network",         "Another HTTP client — can fetch or post data externally."),
    "http":         ("MEDIUM", "Network",         "Low-level HTTP communication."),
    "ftplib":       ("HIGH",   "Network",         "FTP client — can upload files to remote servers."),
    "smtplib":      ("HIGH",   "Network",         "SMTP client — can send emails (data exfiltration vector)."),
    "base64":       ("MEDIUM", "Obfuscation",     "Commonly used to encode/obfuscate payloads or exfiltrate data."),
    "pickle":       ("HIGH",   "Unsafe Deserial.", "Deserializing untrusted pickle data allows arbitrary code execution."),
    "marshal":      ("HIGH",   "Unsafe Deserial.", "Similar to pickle — can execute code on deserialization."),
    "shelve":       ("HIGH",   "Unsafe Deserial.", "Built on pickle — same deserialization risk."),
    "importlib":    ("HIGH",   "Code Execution",  "Allows dynamic module loading — can load malicious code at runtime."),
    "ctypes":       ("HIGH",   "Code Execution",  "Direct access to C libraries — can call arbitrary native code."),
    "cffi":         ("HIGH",   "Code Execution",  "C Foreign Function Interface — similar risk to ctypes."),
    "pty":          ("HIGH",   "Code Execution",  "Provides pseudo-terminal — can spawn interactive shells."),
    "paramiko":     ("HIGH",   "Network",         "SSH client — can connect to remote machines and execute commands."),
    "cryptography": ("MEDIUM", "Crypto",          "Legitimate use is common, but also used to encrypt/decrypt payloads."),
    "Crypto":       ("MEDIUM", "Crypto",          "PyCryptodome — same dual-use as cryptography."),
    "hashlib":      ("LOW",    "Crypto",          "Hashing library — low risk but sometimes used to hash stolen data."),
    "zlib":         ("MEDIUM", "Obfuscation",     "Compression — can be used to pack/unpack obfuscated payloads."),
    "gzip":         ("MEDIUM", "Obfuscation",     "Compression — same dual-use as zlib."),
    "shutil":       ("MEDIUM", "File Access",     "File operations including copy, move, delete of entire trees."),
    "tempfile":     ("LOW",    "File Access",     "Creates temporary files — sometimes used to stage payloads."),
    "glob":         ("LOW",    "File Access",     "File discovery — can be used to map out filesystem contents."),
    "fnmatch":      ("LOW",    "File Access",     "File pattern matching — similar to glob."),
    "winreg":       ("HIGH",   "Persistence",     "Windows Registry access — classic persistence mechanism."),
    "sched":        ("MEDIUM", "Persistence",     "Task scheduler — can be used to create time-triggered logic bombs."),
    "threading":    ("LOW",    "Execution",       "Multi-threading — can be used to hide background activity."),
    "multiprocessing": ("LOW", "Execution",       "Multi-process spawning — can obscure malicious child processes."),
    "signal":       ("MEDIUM", "Execution",       "Signal handling — can intercept and suppress shutdown signals."),
    "platform":     ("LOW",    "Reconnaissance",  "System fingerprinting — OS, hostname, architecture."),
    "getpass":      ("HIGH",   "Credential Theft","Reads passwords from the terminal — strong exfiltration signal."),
    "keyring":      ("HIGH",   "Credential Theft","Reads stored system credentials."),
    "pwd":          ("HIGH",   "Credential Theft","Reads Unix password database entries."),
    "grp":          ("MEDIUM", "Reconnaissance",  "Reads Unix group database — system enumeration."),
    "psutil":       ("MEDIUM", "Reconnaissance",  "Process/system monitoring — can enumerate running processes and connections."),
}

# Dangerous specific calls: call name -> (severity, category, reason)
DANGEROUS_CALLS = {
    "eval":                 ("HIGH",   "Code Execution",  "Executes arbitrary Python expressions from a string."),
    "exec":                 ("HIGH",   "Code Execution",  "Executes arbitrary Python code from a string."),
    "compile":              ("HIGH",   "Code Execution",  "Compiles and can execute arbitrary code strings."),
    "__import__":           ("HIGH",   "Code Execution",  "Dynamic import — can load arbitrary modules at runtime."),
    "os.system":            ("HIGH",   "Code Execution",  "Runs a shell command — direct OS command execution."),
    "os.popen":             ("HIGH",   "Code Execution",  "Opens a pipe to a shell command."),
    "os.execv":             ("HIGH",   "Code Execution",  "Replaces the current process with another program."),
    "os.execve":            ("HIGH",   "Code Execution",  "execve variant — same risk."),
    "os.spawn":             ("HIGH",   "Code Execution",  "Spawns a new process."),
    "os.getenv":            ("LOW",    "Reconnaissance",  "Reads environment variables — can harvest secrets from env."),
    "os.environ":           ("MEDIUM", "Reconnaissance",  "Access to all environment variables."),
    "os.getlogin":          ("LOW",    "Reconnaissance",  "Retrieves the current user's login name."),
    "subprocess.call":      ("HIGH",   "Code Execution",  "Executes a system command."),
    "subprocess.run":       ("HIGH",   "Code Execution",  "Executes a system command (modern API)."),
    "subprocess.Popen":     ("HIGH",   "Code Execution",  "Opens a subprocess — full shell access."),
    "subprocess.check_output": ("HIGH","Code Execution",  "Runs a command and captures its output."),
    "socket.socket":        ("HIGH",   "Network",         "Creates a raw network socket."),
    "socket.connect":       ("HIGH",   "Network",         "Opens a network connection."),
    "requests.get":         ("MEDIUM", "Network",         "HTTP GET — can retrieve remote resources or C2 instructions."),
    "requests.post":        ("HIGH",   "Network",         "HTTP POST — primary vector for exfiltrating data."),
    "requests.put":         ("HIGH",   "Network",         "HTTP PUT — can upload data to a remote server."),
    "requests.delete":      ("MEDIUM", "Network",         "HTTP DELETE — can trigger remote actions."),
    "urllib.request.urlopen": ("MEDIUM","Network",        "Opens a URL — can fetch or post data externally."),
    "urllib.request.urlretrieve": ("MEDIUM","Network",   "Downloads a file from a URL."),
    "base64.b64encode":     ("MEDIUM", "Obfuscation",     "Base64 encoding — often used to hide data before exfiltration."),
    "base64.b64decode":     ("MEDIUM", "Obfuscation",     "Base64 decoding — often used to unpack hidden payloads."),
    "base64.encodebytes":   ("MEDIUM", "Obfuscation",     "Alternate base64 encoder — same risk."),
    "pickle.loads":         ("HIGH",   "Unsafe Deserial.", "Deserializes untrusted data — can execute arbitrary code."),
    "pickle.load":          ("HIGH",   "Unsafe Deserial.", "Same as pickle.loads — file-based deserialization."),
    "marshal.loads":        ("HIGH",   "Unsafe Deserial.", "Deserializes bytecode — can run arbitrary Python code."),
    "importlib.import_module": ("HIGH","Code Execution",  "Dynamically imports a module by name."),
    "ctypes.cdll.LoadLibrary": ("HIGH","Code Execution",  "Loads a native shared library — can call arbitrary C code."),
    "ctypes.windll":        ("HIGH",   "Code Execution",  "Loads Windows DLLs directly."),
    "getpass.getpass":      ("HIGH",   "Credential Theft","Prompts for and captures a password."),
    "winreg.OpenKey":       ("HIGH",   "Persistence",     "Opens a Windows Registry key."),
    "winreg.SetValueEx":    ("HIGH",   "Persistence",     "Writes a value to the Registry — persistence mechanism."),
    "shutil.rmtree":        ("HIGH",   "Destructive",     "Recursively deletes a directory — anti-forensic potential."),
    "os.remove":            ("MEDIUM", "File Access",     "Deletes a file."),
    "os.unlink":            ("MEDIUM", "File Access",     "Same as os.remove."),
    "open":                 ("LOW",    "File Access",     "Opens a file — low risk alone, but combined with network = exfiltration."),
}


def detect_dangerous_apis(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Run both import-level and call-level detection on the parsed AST.

    Returns a list of findings, each containing:
        type        - "import" or "call"
        name        - the flagged name
        lineno      - line number
        severity    - LOW / MEDIUM / HIGH
        category    - risk category string
        reason      - plain-English explanation
    """
    findings = []

    # --- Import-level scan ---
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in RISKY_IMPORTS:
                    sev, cat, reason = RISKY_IMPORTS[root]
                    findings.append({
                        "type": "import",
                        "name": alias.name,
                        "lineno": getattr(node, "lineno", 0),
                        "severity": sev,
                        "category": cat,
                        "reason": reason,
                    })

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                if root in RISKY_IMPORTS:
                    sev, cat, reason = RISKY_IMPORTS[root]
                    findings.append({
                        "type": "import",
                        "name": node.module,
                        "lineno": getattr(node, "lineno", 0),
                        "severity": sev,
                        "category": cat,
                        "reason": reason,
                    })

    # --- Call-level scan ---
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _resolve_call_name(node.func)
            if name in DANGEROUS_CALLS:
                sev, cat, reason = DANGEROUS_CALLS[name]
                findings.append({
                    "type": "call",
                    "name": name,
                    "lineno": getattr(node, "lineno", 0),
                    "severity": sev,
                    "category": cat,
                    "reason": reason,
                })

    # Sort by line number for readable output
    findings.sort(key=lambda f: f["lineno"])
    return findings


def _resolve_call_name(node: ast.expr) -> str:
    """Reconstruct a dotted call name from the AST node (e.g. 'requests.post')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""
