"""
obfuscation_patterns.py
-----------------------
Obfuscation detection patterns for obfuscation_detector.py.
Each entry: (pattern_name, regex, severity, category, reason)
"""

import re
from typing import List, Tuple, Pattern

# ==========================================
# LINE-BASED OBFUSCATION PATTERNS
# ==========================================

LINE_RULES: List[Tuple[str, Pattern, str, str, str]] = [
    # (pattern_name, compiled_regex, severity, category, reason)
    
    # =====================================
    # chr() Chain Obfuscation
    # =====================================
    (
        "chr() chain — string building",
        re.compile(r'(chr\s*\(\s*\d+\s*\)\s*\+\s*){2,}'),
        "HIGH",
        "chr() Chain Obfuscation",
        "Multiple chr() calls concatenated — classic technique to build a string without using string literals, hiding the actual content from static analysis.",
    ),
    
    # =====================================
    # XOR Obfuscation
    # =====================================
    (
        "XOR decode loop",
        re.compile(r'\^\s*(0x[0-9a-fA-F]+|\d+)'),
        "HIGH",
        "XOR Obfuscation",
        "XOR operation with a constant — common in XOR-based payload decryption routines.",
    ),
    
    # =====================================
    # Encoded Payload Execution
    # =====================================
    (
        "Base64 decode → exec/eval",
        re.compile(r'(eval|exec)\s*\([^)]*base64\.(b64decode|decodebytes|decode)', re.IGNORECASE),
        "HIGH",
        "Encoded Payload Execution",
        "Base64-decoded content passed directly to eval()/exec() — classic encoded payload execution pattern.",
    ),
    (
        "Base64 decode → compile",
        re.compile(r'compile\s*\([^)]*base64\.(b64decode|decodebytes)', re.IGNORECASE),
        "HIGH",
        "Encoded Payload Execution",
        "Base64-decoded content passed to compile() — obfuscated code compiled and likely executed.",
    ),
    (
        "zlib decompress + base64 decode chain",
        re.compile(r'zlib\.decompress\s*\([^)]*base64\.b64decode|base64\.b64decode[^)]*zlib\.decompress', re.IGNORECASE),
        "HIGH",
        "Packed Payload",
        "zlib decompression chained with base64 decoding — signature of a packed/compressed payload being unpacked at runtime.",
    ),
    (
        "eval/exec with decode chain",
        re.compile(r'(eval|exec)\s*\([^)]*\.(decode|decompress)\s*\(', re.IGNORECASE),
        "HIGH",
        "Encoded Payload Execution",
        "eval()/exec() called on decoded/decompressed content — encoded payload being unpacked and executed.",
    ),
    
    # =====================================
    # Dynamic Import Obfuscation
    # =====================================
    (
        "Dynamic __import__() call",
        re.compile(r'__import__\s*\(\s*(?!["\'][a-zA-Z_][a-zA-Z0-9_.]*["\'])'),
        "HIGH",
        "Dynamic Import Obfuscation",
        "__import__() called with a non-literal argument — module name is determined at runtime to evade static import analysis.",
    ),
    (
        "String concat to build module name",
        re.compile(r'__import__\s*\(\s*["\'][a-z]+["\'\s]*\+\s*["\'][a-z]+["\']'),
        "HIGH",
        "Import Name Obfuscation",
        "Module name built by string concatenation before __import__ — hides which module is being imported.",
    ),
    
    # =====================================
    # Runtime Code Compilation
    # =====================================
    (
        "exec(compile()) — runtime code compilation",
        re.compile(r'exec\s*\(\s*compile\s*\('),
        "HIGH",
        "Runtime Code Compilation",
        "exec(compile(...)) — code is compiled and executed at runtime, bypassing static analysis of what runs.",
    ),
    
    # =====================================
    # Escape Sequence Obfuscation
    # =====================================
    (
        "Hex escape sequences in string",
        re.compile(r'(\\x[0-9a-fA-F]{2}){4,}'),
        "MEDIUM",
        "Hex Escape Obfuscation",
        "Four or more consecutive hex escape sequences — commonly used to encode hidden strings or shellcode.",
    ),
    (
        "Octal escape sequences in string",
        re.compile(r'(\\[0-7]{3}){3,}'),
        "MEDIUM",
        "Octal Escape Obfuscation",
        "Multiple octal escape sequences — alternate encoding method to hide string content from static inspection.",
    ),
    (
        "Unicode escape sequences in string",
        re.compile(r'(\\u[0-9a-fA-F]{4}){3,}'),
        "MEDIUM",
        "Unicode Escape Obfuscation",
        "Multiple Unicode escape sequences — can be used to hide keywords or strings from pattern matching.",
    ),
    
    # =====================================
    # Dynamic Attribute Resolution
    # =====================================
    (
        "getattr() used to call function dynamically",
        re.compile(r'getattr\s*\(\s*\w+\s*,\s*(?!["\'][a-zA-Z_][a-zA-Z0-9_]*["\'])[^)]+\)'),
        "MEDIUM",
        "Dynamic Attribute Resolution",
        "getattr() called with a non-literal attribute name — function to call is determined at runtime, hiding behavior.",
    ),
    
    # =====================================
    # Lambda Chain Obfuscation
    # =====================================
    (
        "Lambda chain obfuscation",
        re.compile(r'(lambda\s+\w+\s*:\s*){3,}'),
        "MEDIUM",
        "Lambda Chain Obfuscation",
        "Deeply nested lambda expressions — can be used to obfuscate logic and evade simple pattern matching.",
    ),
    
    # =====================================
    # Encoding Obfuscation
    # =====================================
    (
        "codecs.decode / rot13 obfuscation",
        re.compile(r'codecs\.(decode|encode)\s*\([^)]*["\']rot.?13["\']|["\']rot.?13["\'][^)]*codecs\.(decode|encode)', re.IGNORECASE),
        "HIGH",
        "Encoding Obfuscation",
        "codecs.decode with rot13 — used to hide string literals like function names or URLs from static inspection.",
    ),
]

# ==========================================
# ENTROPY CONFIGURATION
# ==========================================

ENTROPY_THRESHOLD = 5.0   # bits per character
MIN_ENTROPY_LENGTH = 80   # minimum string length for entropy check


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "LINE_RULES",
    "ENTROPY_THRESHOLD",
    "MIN_ENTROPY_LENGTH",
]