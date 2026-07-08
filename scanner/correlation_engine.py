"""
correlation_engine.py
---------------------
Converts raw data-flow findings into security detections.

This module correlates behavioral features and data flows to identify
attack patterns defined in scanner/data/attack_patterns.py.
"""

from typing import Dict, Any, List, Optional, Set, Tuple

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.attack_patterns import ATTACK_PATTERNS
from scanner.data.confidence_weights import EVIDENCE_WEIGHTS
from scanner.data.priority_rules import (
    PRIORITY_RULES,
    SUPPRESSION_RULES,
    get_suppressed_attacks,
    get_priority,
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _get_source_weight(source: str) -> int:
    """Get weight for a source type."""
    return EVIDENCE_WEIGHTS.get("source", {}).get(source, 8)


def _get_transform_weight(count: int) -> int:
    """Get weight for number of transforms."""
    t_weights = EVIDENCE_WEIGHTS.get("transform_count", {0: 0, 1: 10, 2: 18, 3: 25, 4: 30})
    if count >= 4:
        return t_weights.get(4, 30)
    return t_weights.get(count, 5)


def _get_sink_weight(sink: str) -> int:
    """Get weight for a sink type."""
    sink_weights = EVIDENCE_WEIGHTS.get("sink", {})
    for prefix, weight in sink_weights.items():
        if sink.startswith(prefix):
            return weight
    return 8


def _get_behavior_weights(behaviors: Dict[str, Any]) -> int:
    """Calculate total weight from enabled behaviors."""
    behavior_weights = EVIDENCE_WEIGHTS.get("behaviors", {})
    total = 0
    for behavior, weight in behavior_weights.items():
        if behaviors.get(behavior, False):
            total += weight
    return total


def _get_bonus_weight(bonus_type: str, default: int = 0) -> int:
    """Get weight for a bonus."""
    return EVIDENCE_WEIGHTS.get("bonuses", {}).get(bonus_type, default)


def _get_min_confidence(attack_type: str) -> int:
    """Get minimum confidence for an attack type."""
    return EVIDENCE_WEIGHTS.get("min_confidence", {}).get(attack_type, 30)


# ==========================================
# CONFIDENCE CALCULATOR
# ==========================================

def calculate_confidence(
    attack_type: str,
    evidence: Dict[str, Any],
    behaviors: Dict[str, Any]
) -> int:
    """Calculate confidence score dynamically based on evidence strength."""
    confidence = 50  # Base confidence
    
    # Source weight
    source = evidence.get("source", "unknown")
    confidence += _get_source_weight(source)
    
    # Transform weight
    transforms = evidence.get("transforms", [])
    confidence += _get_transform_weight(len(transforms))
    
    # Sink weight
    sink = evidence.get("sink", "unknown")
    confidence += _get_sink_weight(sink)
    
    # Behavior weights
    confidence += _get_behavior_weights(behaviors)
    
    # Bonuses
    if source != "unknown" and sink != "unknown":
        confidence += _get_bonus_weight("complete_flow")
    
    # ✅ FIX: Check if source is credential/env_var and sink is requests
    if source in ["credential", "env_var"] and "requests" in sink:
        confidence += _get_bonus_weight("sensitive_to_network")
    
    if len(transforms) >= 3:
        confidence += _get_bonus_weight("complex_transforms")
    
    # Apply minimum confidence
    min_conf = _get_min_confidence(attack_type)
    if confidence < min_conf:
        confidence = min_conf
    
    return min(max(confidence, 0), 100)


# ==========================================
# CONDITION MATCHING
# ==========================================

def _match_flow_conditions(flow: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
    """
    Check if a flow matches the conditions for an attack pattern.
    
    Args:
        flow: Data flow dictionary
        conditions: Pattern conditions dictionary
        
    Returns:
        True if flow matches conditions
    """
    source = flow.get("source", "")
    
    # Check source condition
    if "source" in conditions:
        required = conditions["source"]
        if isinstance(required, list):
            if source not in required:
                return False
        elif source != required:
            return False
    
    # Check transform requirement
    if conditions.get("transforms_required", False):
        if not flow.get("transforms"):
            return False
    
    # Check sink prefix
    if "sink_prefix" in conditions:
        sink = flow.get("sink", "")
        if not sink.startswith(conditions["sink_prefix"]):
            return False
    
    return True


def _match_behavior_conditions(behaviors: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
    """
    Check if behaviors match the conditions for an attack pattern.
    
    Args:
        behaviors: Behavioral feature vector
        conditions: Pattern conditions dictionary
        
    Returns:
        True if behaviors match conditions
    """
    if "behaviors" in conditions:
        required = conditions["behaviors"]
        for key, value in required.items():
            if behaviors.get(key, False) != value:
                return False
        return True
    return False


def _get_matched_behaviors(behaviors: Dict[str, Any], conditions: Dict[str, Any]) -> Dict[str, bool]:
    """
    Get the matched behaviors from conditions.
    """
    matched = {}
    if "behaviors" in conditions:
        required = conditions["behaviors"]
        for key in required:
            matched[key] = behaviors.get(key, False)
    return matched


# ==========================================
# FINDING CREATION
# ==========================================

def _create_flow_finding(
    attack_type: str,
    pattern: Dict[str, Any],
    flow: Dict[str, Any],
    behaviors: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create a finding from a flow-based match.
    """
    confidence = calculate_confidence(attack_type, flow, behaviors)
    
    return {
        "attack_type": attack_type,
        "description": pattern.get("description", ""),
        "severity": pattern.get("severity", "MEDIUM"),
        "confidence": confidence,
        "evidence": flow,
    }


def _create_behavior_finding(
    attack_type: str,
    pattern: Dict[str, Any],
    behaviors: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create a finding from a behavior-based match.
    """
    confidence = calculate_confidence(attack_type, {}, behaviors)
    
    return {
        "attack_type": attack_type,
        "description": pattern.get("description", ""),
        "severity": pattern.get("severity", "MEDIUM"),
        "confidence": confidence,
        "evidence": {
            "matched_behaviors": _get_matched_behaviors(
                behaviors,
                pattern.get("conditions", {})
            )
        },
    }


# ==========================================
# CORRELATION ENGINE
# ==========================================

def correlate_behaviors(
    flows: List[Dict[str, Any]],
    behaviors: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Correlate behavioral features and data flows to identify attack patterns.
    
    Args:
        flows: List of data flow dictionaries from source_sink_tracker
        behaviors: Behavioral feature vector
        
    Returns:
        List of correlated attack findings
    """
    findings = []
    processed_flow_attacks = set()
    
    for attack_type, pattern in ATTACK_PATTERNS.items():
        conditions = pattern.get("conditions", {})
        pattern_type = pattern.get("type", "")
        
        # Check flow-based patterns
        if pattern_type in ["flow_based", "flow_behavior_based"]:
            for flow in flows:
                if _match_flow_conditions(flow, conditions):
                    # Avoid duplicate flow-based findings for same attack type
                    if attack_type not in processed_flow_attacks:
                        findings.append(_create_flow_finding(attack_type, pattern, flow, behaviors))
                        processed_flow_attacks.add(attack_type)
                    break
        
        # Check behavior-based patterns
        if pattern_type in ["behavior_based", "flow_behavior_based"]:
            if _match_behavior_conditions(behaviors, conditions):
                findings.append(_create_behavior_finding(attack_type, pattern, behaviors))
    
    # Prioritize findings
    return prioritize_findings(findings)


# ==========================================
# PRIORITIZATION ENGINE
# ==========================================

def prioritize_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prioritize findings based on priority rules.
    
    Rules:
        1. Higher priority attacks suppress lower priority attacks
        2. Duplicate attack types are deduplicated (keep highest confidence)
        3. Findings are sorted by priority (highest first)
    
    Args:
        findings: List of attack findings
        
    Returns:
        Prioritized and deduplicated list of findings
    """
    if not findings:
        return []
    
    # Get unique attack types
    attack_types = {f.get("attack_type") for f in findings if f.get("attack_type")}
    
    # Build suppression map
    suppressed = set()
    for attack_type in attack_types:
        suppressed_attacks = get_suppressed_attacks(attack_type)
        suppressed.update(suppressed_attacks)
    
    # Filter out suppressed findings
    filtered = [
        f for f in findings
        if f.get("attack_type") not in suppressed
    ]
    
    # Deduplicate (keep highest confidence)
    seen = {}
    for finding in filtered:
        attack_type = finding.get("attack_type")
        if attack_type:
            confidence = finding.get("confidence", 0)
            if attack_type not in seen or confidence > seen[attack_type]["confidence"]:
                seen[attack_type] = finding
    
    # Sort by priority (highest first)
    result = list(seen.values())
    result.sort(
        key=lambda x: get_priority(x.get("attack_type", "")),
        reverse=True
    )
    
    return result


# ==========================================
# HELPER: GET SUMMARY
# ==========================================

def get_correlation_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get a summary of correlation findings.
    
    Args:
        findings: List of attack findings
        
    Returns:
        Summary dictionary with counts and breakdowns
    """
    if not findings:
        return {
            "total": 0,
            "by_severity": {},
            "by_attack_type": {},
            "max_confidence": 0,
            "avg_confidence": 0,
        }
    
    by_severity = {}
    by_attack_type = {}
    total_confidence = 0
    max_confidence = 0
    
    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        attack_type = finding.get("attack_type", "UNKNOWN")
        by_attack_type[attack_type] = by_attack_type.get(attack_type, 0) + 1
        
        confidence = finding.get("confidence", 0)
        total_confidence += confidence
        max_confidence = max(max_confidence, confidence)
    
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_attack_type": by_attack_type,
        "max_confidence": max_confidence,
        "avg_confidence": round(total_confidence / len(findings), 2),
    }


# ==========================================
# LEGACY SUPPORT
# ==========================================

def correlate_behaviors_legacy(
    flows: List[Dict[str, Any]],
    behaviors: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return correlate_behaviors(flows, behaviors)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "correlate_behaviors",
    "correlate_behaviors_legacy",
    "calculate_confidence",
    "prioritize_findings",
    "get_correlation_summary",
    "ATTACK_PATTERNS",
]