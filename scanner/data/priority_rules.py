"""
priority_rules.py
-----------------
Priority and suppression rules for attack findings.
Controls which attacks take precedence when multiple are detected.

To modify priorities, simply update the dictionaries below.
No code changes needed!
"""

from typing import Dict, List, Set

# ==========================================
# PRIORITY RULES
# Higher number = higher priority
# ==========================================

PRIORITY_RULES: Dict[str, int] = {
    "STEALTHY_DATA_EXFILTRATION": 100,
    "OBFUSCATED_CREDENTIAL_EXFILTRATION": 95,
    "ADVANCED_CREDENTIAL_THEFT": 90,
    "CREDENTIAL_THEFT": 85,
    "OBFUSCATED_DATA_EXFILTRATION": 80,
    "DATA_EXFILTRATION": 70,
    "INPUT_COLLECTION": 60,
    "BACKDOOR": 95,
    "RANSOMWARE": 94,
    "LOGIC_BOMB": 96,
}


# ==========================================
# SUPPRESSION RULES
# When a high-priority attack is detected,
# these lower-priority attacks are suppressed
# ==========================================

SUPPRESSION_RULES: Dict[str, List[str]] = {
    "STEALTHY_DATA_EXFILTRATION": [
        "DATA_EXFILTRATION",
        "OBFUSCATED_DATA_EXFILTRATION",
    ],
    "OBFUSCATED_CREDENTIAL_EXFILTRATION": [
        "CREDENTIAL_THEFT",
        "ADVANCED_CREDENTIAL_THEFT",
    ],
    "BACKDOOR": [
        "CREDENTIAL_THEFT",
        "INPUT_COLLECTION",
    ],
    "RANSOMWARE": [
        "DATA_EXFILTRATION",
        "OBFUSCATED_DATA_EXFILTRATION",
    ],
    "LOGIC_BOMB": [
        "CREDENTIAL_THEFT",
        "INPUT_COLLECTION",
    ],
}


# ==========================================
# CONFIDENCE ADJUSTMENTS
# ==========================================

# Add confidence bonuses when multiple evidence types are present
CONFIDENCE_BONUSES: Dict[str, int] = {
    "has_source": 5,
    "has_sink": 5,
    "has_transforms": 10,
    "multiple_transforms": 15,
    "has_behavior_evidence": 10,
    "has_flow_evidence": 5,
}


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def get_priority(attack_type: str) -> int:
    """
    Get priority of an attack type.
    
    Args:
        attack_type: Type of attack
        
    Returns:
        Priority score (higher = more important)
    """
    return PRIORITY_RULES.get(attack_type, 50)


def get_suppressed_attacks(attack_type: str) -> List[str]:
    """
    Get list of attacks suppressed by this attack type.
    
    Args:
        attack_type: Attack that suppresses others
        
    Returns:
        List of suppressed attack types
    """
    return SUPPRESSION_RULES.get(attack_type, [])


def get_suppression_map() -> Dict[str, Set[str]]:
    """
    Get full suppression mapping as a set for fast lookup.
    
    Returns:
        Dict mapping attack type to set of suppressed types
    """
    return {
        k: set(v) for k, v in SUPPRESSION_RULES.items()
    }


def get_confidence_bonus(bonus_type: str) -> int:
    """
    Get confidence bonus for a specific type.
    
    Args:
        bonus_type: Type of bonus
        
    Returns:
        Bonus amount
    """
    return CONFIDENCE_BONUSES.get(bonus_type, 0)


__all__ = [
    "PRIORITY_RULES",
    "SUPPRESSION_RULES",
    "CONFIDENCE_BONUSES",
    "get_priority",
    "get_suppressed_attacks",
    "get_suppression_map",
    "get_confidence_bonus",
]