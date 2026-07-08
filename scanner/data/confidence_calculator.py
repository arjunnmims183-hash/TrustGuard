"""
confidence_calculator.py
------------------------
Calculates dynamic confidence scores based on evidence.
"""

from typing import Dict, Any, List
from scanner.data.confidence_weights import EVIDENCE_WEIGHTS


def calculate_confidence(
    attack_type: str,
    evidence: Dict[str, Any],
    behaviors: Dict[str, Any],
    weights: Dict[str, Any] = None
) -> int:
    """
    Calculate confidence dynamically based on evidence.
    
    Args:
        attack_type: Type of attack
        evidence: Evidence from the detection
        behaviors: Behavioral feature vector
        weights: Optional custom weights (uses defaults if None)
        
    Returns:
        Confidence score (0-100)
    """
    if weights is None:
        weights = EVIDENCE_WEIGHTS
    
    confidence = 0
    details = []
    
    # ==========================================
    # SOURCE WEIGHT
    # ==========================================
    source = evidence.get("source", "unknown")
    source_weight = weights["source"].get(source, 5)
    confidence += source_weight
    details.append(f"source ({source}): +{source_weight}")
    
    # ==========================================
    # TRANSFORM WEIGHT
    # ==========================================
    transforms = evidence.get("transforms", [])
    transform_count = len(transforms)
    
    # Get closest transform count weight
    if transform_count >= 4:
        transform_weight = weights["transform_count"][4]
    elif transform_count in weights["transform_count"]:
        transform_weight = weights["transform_count"][transform_count]
    else:
        transform_weight = 5
    
    confidence += transform_weight
    details.append(f"transforms ({transform_count}): +{transform_weight}")
    
    # ==========================================
    # SINK WEIGHT
    # ==========================================
    sink = evidence.get("sink", "unknown")
    sink_weight = 8  # Default
    
    for sink_prefix, weight in weights["sink"].items():
        if sink.startswith(sink_prefix):
            sink_weight = weight
            break
    
    confidence += sink_weight
    details.append(f"sink ({sink}): +{sink_weight}")
    
    # ==========================================
    # BEHAVIOR WEIGHTS
    # ==========================================
    behavior_weight = 0
    matched_behaviors = []
    
    for behavior, weight in weights["behaviors"].items():
        if behaviors.get(behavior, False):
            behavior_weight += weight
            matched_behaviors.append(behavior)
    
    confidence += behavior_weight
    if matched_behaviors:
        details.append(f"behaviors ({', '.join(matched_behaviors)}): +{behavior_weight}")
    
    # ==========================================
    # BONUSES
    # ==========================================
    bonuses = weights["bonuses"]
    
    # Complete flow bonus
    if source and sink:
        confidence += bonuses["complete_flow"]
        details.append(f"complete flow: +{bonuses['complete_flow']}")
    
    # Multiple behaviors bonus
    if len(matched_behaviors) >= 2:
        confidence += bonuses["multiple_behaviors"]
        details.append(f"multiple behaviors: +{bonuses['multiple_behaviors']}")
    
    # Complex transforms bonus
    if transform_count >= 3:
        confidence += bonuses["complex_transforms"]
        details.append(f"complex transforms: +{bonuses['complex_transforms']}")
    
    # ==========================================
    # APPLY MINIMUM CONFIDENCE
    # ==========================================
    min_confidence = weights["min_confidence"].get(attack_type, 30)
    if confidence < min_confidence:
        confidence = min_confidence
        details.append(f"minimum confidence applied: {min_confidence}")
    
    # ==========================================
    # CLAMP TO 0-100
    # ==========================================
    final_confidence = min(max(confidence, 0), 100)
    
    return final_confidence


def get_confidence_breakdown(
    attack_type: str,
    evidence: Dict[str, Any],
    behaviors: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Get detailed breakdown of confidence calculation.
    
    Returns:
        Dictionary with confidence and breakdown details
    """
    # Use the same calculation but track details
    # For now, just return the confidence
    confidence = calculate_confidence(attack_type, evidence, behaviors)
    
    return {
        "confidence": confidence,
        "attack_type": attack_type,
        "evidence": evidence,
        "behaviors": behaviors,
    }


__all__ = [
    "calculate_confidence",
    "get_confidence_breakdown",
]