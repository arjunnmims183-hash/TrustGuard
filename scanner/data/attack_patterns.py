"""
attack_patterns.py
------------------
Attack pattern definitions ONLY.
All weights are in confidence_weights.py.
All priorities are in priority_rules.py.
All scoring weights are in attack_weights.py.

To add a new attack pattern:
1. Add a new entry to ATTACK_PATTERNS below
2. Optionally add min_confidence in confidence_weights.py
3. Optionally add priority in priority_rules.py
4. Optionally add scoring weights in attack_weights.py

NO weights or priorities should be defined here!
"""

from typing import Dict, Any, List, Optional

# ==========================================
# ATTACK PATTERN DEFINITIONS
# ==========================================

ATTACK_PATTERNS: Dict[str, Dict[str, Any]] = {
    
    # =====================================
    # CREDENTIAL THEFT
    # =====================================
    "CREDENTIAL_THEFT": {
        "description": "Credentials are being accessed and exfiltrated",
        "severity": "CRITICAL",
        "type": "flow_based",
        "conditions": {
            "source": ["env_var", "credential"],
        },
        "mitre_techniques": ["T1552"],
    },
    
    # =====================================
    # OBFUSCATED DATA EXFILTRATION
    # =====================================
    "OBFUSCATED_DATA_EXFILTRATION": {
        "description": "Data is being obfuscated and exfiltrated",
        "severity": "HIGH",
        "type": "flow_based",
        "conditions": {
            "source": "file_read",
            "transforms_required": True,
        },
        "mitre_techniques": ["T1027", "T1041"],
    },
    
    # =====================================
    # DATA EXFILTRATION
    # =====================================
    "DATA_EXFILTRATION": {
        "description": "Data is being read and transmitted externally",
        "severity": "MEDIUM",
        "type": "flow_based",
        "conditions": {
            "source": "file_read",
        },
        "mitre_techniques": ["T1041"],
    },
    
    # =====================================
    # INPUT COLLECTION
    # =====================================
    "INPUT_COLLECTION": {
        "description": "User input is being collected and transmitted",
        "severity": "MEDIUM",
        "type": "flow_based",
        "conditions": {
            "source": "user_input",
        },
        "mitre_techniques": ["T1056"],
    },
    
    # =====================================
    # STEALTHY DATA EXFILTRATION
    # =====================================
    "STEALTHY_DATA_EXFILTRATION": {
        "description": "Stealthy data exfiltration with anti-forensics",
        "severity": "CRITICAL",
        "type": "flow_behavior_based",
        "conditions": {
            "source": "file_read",
            "transforms_required": True,
            "behavior_required": "anti_forensics",
        },
        "mitre_techniques": ["T1070", "T1041"],
    },
    
    # =====================================
    # OBFUSCATED CREDENTIAL EXFILTRATION
    # =====================================
    "OBFUSCATED_CREDENTIAL_EXFILTRATION": {
        "description": "Credentials are obfuscated and exfiltrated",
        "severity": "CRITICAL",
        "type": "flow_based",
        "conditions": {
            "source": ["env_var", "credential"],
            "transforms_required": True,
            "sink_prefix": "requests",
        },
        "mitre_techniques": ["T1552", "T1027", "T1041"],
    },
    
    # =====================================
    # ADVANCED CREDENTIAL THEFT
    # =====================================
    "ADVANCED_CREDENTIAL_THEFT": {
        "description": "Advanced credential theft with multiple techniques",
        "severity": "CRITICAL",
        "type": "behavior_based",
        "conditions": {
            "behaviors": {
                "credential_access": True,
                "network_request": True,
                "obfuscation": True,
            }
        },
        "mitre_techniques": ["T1552", "T1027"],
    },
    
    # =====================================
    # BACKDOOR DETECTION
    # =====================================
    "BACKDOOR": {
        "description": "Backdoor functionality detected",
        "severity": "CRITICAL",
        "type": "behavior_based",
        "conditions": {
            "behaviors": {
                "network_request": True,
                "subprocess": True,
            }
        },
        "mitre_techniques": ["T1505"],
    },
    
    # =====================================
    # RANSOMWARE
    # =====================================
    "RANSOMWARE": {
        "description": "Ransomware-like behavior detected",
        "severity": "CRITICAL",
        "type": "behavior_based",
        "conditions": {
            "behaviors": {
                "file_read": True,
                "file_write": True,
                "obfuscation": True,
            }
        },
        "mitre_techniques": ["T1486", "T1490"],
    },
    
    # =====================================
    # LOGIC BOMB
    # =====================================
    "LOGIC_BOMB": {
        "description": "Logic bomb detected with conditional malicious code",
        "severity": "CRITICAL",
        "type": "behavior_based",
        "conditions": {
            "behaviors": {
                "logic_bomb": True,
                "eval_usage": True,
            }
        },
        "mitre_techniques": ["T1490"],
    },
}


# ==========================================
# PATTERN TYPE DEFINITIONS
# ==========================================

PATTERN_TYPES: Dict[str, str] = {
    "flow_based": "Detected from data flow analysis (source → transforms → sink)",
    "behavior_based": "Detected from behavioral feature vector",
    "flow_behavior_based": "Detected from combination of flow and behavior",
}


# ==========================================
# CONDITION REFERENCE
# ==========================================

CONDITION_REFERENCE: Dict[str, str] = {
    "source": "Data source type (file_read, env_var, credential, user_input, network_recv)",
    "transforms_required": "Requires at least one transform (True/False)",
    "sink_prefix": "Sink must start with this prefix (e.g., 'requests')",
    "behavior_required": "Behavior must be True (e.g., 'anti_forensics')",
    "behaviors": "Dictionary of behavior_name: required_value",
}


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def get_attack_pattern(attack_type: str) -> Dict[str, Any]:
    """
    Get attack pattern by type.
    
    Args:
        attack_type: Type of attack
        
    Returns:
        Attack pattern dictionary or empty dict if not found
    """
    return ATTACK_PATTERNS.get(attack_type, {})


def get_attack_types() -> List[str]:
    """
    Get all available attack types.
    
    Returns:
        List of attack type names
    """
    return list(ATTACK_PATTERNS.keys())


def get_attacks_by_severity(severity: str) -> List[Dict[str, Any]]:
    """
    Get attacks by severity level.
    
    Args:
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        
    Returns:
        List of attack patterns matching the severity
    """
    return [
        pattern for pattern in ATTACK_PATTERNS.values()
        if pattern.get("severity") == severity
    ]


def get_attacks_by_type(pattern_type: str) -> List[Dict[str, Any]]:
    """
    Get attacks by pattern type.
    
    Args:
        pattern_type: Type of attack pattern 
            (flow_based, behavior_based, flow_behavior_based)
        
    Returns:
        List of attack patterns matching the type
    """
    return [
        pattern for pattern in ATTACK_PATTERNS.values()
        if pattern.get("type") == pattern_type
    ]


def get_attacks_with_condition(condition_key: str, condition_value: Any) -> List[Dict[str, Any]]:
    """
    Get attacks that have a specific condition.
    
    Args:
        condition_key: The condition key (e.g., 'source', 'behavior_required')
        condition_value: The condition value to match
        
    Returns:
        List of attack patterns matching the condition
    """
    results = []
    for attack_type, pattern in ATTACK_PATTERNS.items():
        conditions = pattern.get("conditions", {})
        if condition_key in conditions:
            value = conditions[condition_key]
            if isinstance(value, list) and condition_value in value:
                results.append(pattern)
            elif value == condition_value:
                results.append(pattern)
    return results


def get_attacks_by_behavior(behavior_name: str) -> List[str]:
    """
    Get attack types that require a specific behavior.
    
    Args:
        behavior_name: Name of the behavior
        
    Returns:
        List of attack type names
    """
    results = []
    for attack_type, pattern in ATTACK_PATTERNS.items():
        conditions = pattern.get("conditions", {})
        
        # Check behavior_required
        if conditions.get("behavior_required") == behavior_name:
            results.append(attack_type)
        
        # Check behaviors dict
        behaviors = conditions.get("behaviors", {})
        if behavior_name in behaviors:
            results.append(attack_type)
    
    return results


def validate_attack_pattern(pattern: Dict[str, Any]) -> bool:
    """
    Validate an attack pattern has all required fields.
    
    Args:
        pattern: Attack pattern dictionary
        
    Returns:
        True if valid, False otherwise
    """
    required_fields = ["description", "severity", "type", "conditions"]
    
    for field in required_fields:
        if field not in pattern:
            return False
    
    # Validate severity
    if pattern["severity"] not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        return False
    
    # Validate type
    if pattern["type"] not in ["flow_based", "behavior_based", "flow_behavior_based"]:
        return False
    
    return True


def validate_all_patterns() -> Dict[str, bool]:
    """
    Validate all attack patterns.
    
    Returns:
        Dictionary of attack_type → validation result
    """
    results = {}
    for attack_type, pattern in ATTACK_PATTERNS.items():
        results[attack_type] = validate_attack_pattern(pattern)
    return results


def get_pattern_summary() -> Dict[str, Any]:
    """
    Get a summary of all attack patterns.
    
    Returns:
        Dictionary with counts and statistics
    """
    types = {}
    severities = {}
    
    for pattern in ATTACK_PATTERNS.values():
        pattern_type = pattern.get("type", "unknown")
        types[pattern_type] = types.get(pattern_type, 0) + 1
        
        severity = pattern.get("severity", "unknown")
        severities[severity] = severities.get(severity, 0) + 1
    
    return {
        "total": len(ATTACK_PATTERNS),
        "by_type": types,
        "by_severity": severities,
        "attack_types": list(ATTACK_PATTERNS.keys()),
    }


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "ATTACK_PATTERNS",
    "PATTERN_TYPES",
    "CONDITION_REFERENCE",
    "get_attack_pattern",
    "get_attack_types",
    "get_attacks_by_severity",
    "get_attacks_by_type",
    "get_attacks_with_condition",
    "get_attacks_by_behavior",
    "validate_attack_pattern",
    "validate_all_patterns",
    "get_pattern_summary",
]