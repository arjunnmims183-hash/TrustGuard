"""
attack_scorer_weights.py
------------------------
Weight configurations for attack_scorer.py.
"""

from typing import Dict

# ==========================================
# SOURCE WEIGHTS
# ==========================================

SOURCE_SCORES: Dict[str, int] = {
    "file_read": 20,
    "env_var": 40,
    "credential": 50,
    "user_input": 15,
    "network_recv": 25,
    "os_getenv": 40,
    "environment": 35,
}

# ==========================================
# TRANSFORM WEIGHTS
# ==========================================

TRANSFORM_SCORES: Dict[str, int] = {
    "encode": 5,
    "base64_encode": 15,
    "zlib_compress": 20,
    "gzip_compress": 20,
    "hexlify": 15,
    "serialize": 25,
    "json_serialize": 10,
    "pickle_serialize": 25,
    "encrypt": 30,
    "xor": 15,
}

# ==========================================
# SINK WEIGHTS
# ==========================================

SINK_SCORES: Dict[str, int] = {
    "requests.post": 20,
    "requests.put": 20,
    "requests.patch": 20,
    "socket.send": 25,
    "socket.sendall": 25,
    "smtplib.SMTP.sendmail": 30,
    "ftplib.FTP.storbinary": 25,
    "subprocess.run": 30,
    "os.system": 30,
    "eval": 35,
    "exec": 35,
}

# ==========================================
# THRESHOLDS
# ==========================================

THRESHOLDS: Dict[str, int] = {
    "CRITICAL": 90,
    "HIGH": 70,
    "MEDIUM": 40,
}

# ==========================================
# COMPLEXITY BONUSES
# ==========================================

COMPLEXITY_BONUSES: Dict[int, int] = {
    2: 15,   # 2+ transforms
    4: 20,   # 4+ transforms
    6: 25,   # 6+ transforms
}

# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "SOURCE_SCORES",
    "TRANSFORM_SCORES",
    "SINK_SCORES",
    "THRESHOLDS",
    "COMPLEXITY_BONUSES",
]