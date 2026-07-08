"""
attack_weights.py
-----------------
Weights for attack scoring.
Each attack type can have custom weights for different components.
"""

from typing import Dict, Any

# ==========================================
# ATTACK WEIGHT CONFIGURATIONS
# ==========================================

ATTACK_WEIGHTS: Dict[str, Dict[str, Any]] = {
    "CREDENTIAL_THEFT": {
        "source_weight": 50,
        "sink_weight": 30,
        "transform_weight": 10,
        "complexity_bonus": 10,
    },
    "OBFUSCATED_CREDENTIAL_EXFILTRATION": {
        "source_weight": 50,
        "sink_weight": 30,
        "transform_weight": 15,
        "complexity_bonus": 20,
    },
    "STEALTHY_DATA_EXFILTRATION": {
        "source_weight": 40,
        "sink_weight": 30,
        "transform_weight": 15,
        "complexity_bonus": 25,
    },
    "BACKDOOR": {
        "source_weight": 45,
        "sink_weight": 35,
        "transform_weight": 10,
        "complexity_bonus": 15,
    },
    "RANSOMWARE": {
        "source_weight": 40,
        "sink_weight": 30,
        "transform_weight": 15,
        "complexity_bonus": 20,
    },
    "LOGIC_BOMB": {
        "source_weight": 50,
        "sink_weight": 25,
        "transform_weight": 10,
        "complexity_bonus": 25,
    },
}

# Default weights if attack type not found
DEFAULT_WEIGHTS = {
    "source_weight": 30,
    "sink_weight": 20,
    "transform_weight": 10,
    "complexity_bonus": 10,
}


def get_attack_weights(attack_type: str) -> Dict[str, Any]:
    """
    Get weights for an attack type.
    
    Args:
        attack_type: Type of attack
        
    Returns:
        Dictionary of weights
    """
    return ATTACK_WEIGHTS.get(attack_type, DEFAULT_WEIGHTS)


__all__ = [
    "ATTACK_WEIGHTS",
    "DEFAULT_WEIGHTS",
    "get_attack_weights",
]