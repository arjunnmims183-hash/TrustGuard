"""
confidence_weights.py
---------------------
Weights for calculating confidence scores dynamically.
Easily tunable without code changes.
"""

EVIDENCE_WEIGHTS = {
    # Source weights (0-25)
    "source": {
        "credential": 25,
        "env_var": 22,
        "file_read": 18,
        "user_input": 15,
        "network_recv": 12,
        "unknown": 8,
    },
    
    # Transform count weights (0-25)
    "transform_count": {
        0: 0,
        1: 10,
        2: 18,
        3: 25,
        4: 30,  # 4+ transforms
    },
    
    # Sink weights (0-20)
    "sink": {
        "socket": 20,
        "requests": 18,
        "smtp": 16,
        "ftp": 15,
        "subprocess": 18,
        "eval": 20,
        "unknown": 8,
    },
    
    # Behavior weights (0-15)
    "behaviors": {
        "anti_forensics": 15,
        "credential_access": 12,
        "obfuscation": 10,
        "persistence_attempt": 12,
        "system_recon": 8,
        "subprocess": 10,
    },
    
    # Bonus weights
    "bonuses": {
        "complete_flow": 10,
        "multiple_behaviors": 8,
        "complex_transforms": 10,
        "known_pattern": 15,
    },
    
    # Minimum confidence per attack type
    "min_confidence": {
        "STEALTHY_DATA_EXFILTRATION": 60,
        "OBFUSCATED_CREDENTIAL_EXFILTRATION": 60,
        "ADVANCED_CREDENTIAL_THEFT": 55,
        "CREDENTIAL_THEFT": 50,
        "LOGIC_BOMB": 50,
        "RANSOMWARE": 50,
        "BACKDOOR": 45,
        "DATA_EXFILTRATION": 40,
        "OBFUSCATED_DATA_EXFILTRATION": 45,
        "INPUT_COLLECTION": 35,
    },
}