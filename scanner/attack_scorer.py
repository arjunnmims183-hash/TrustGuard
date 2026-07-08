"""
attack_scorer.py
----------------
Assigns a complexity/threat score to an attack flow.

Example:
    file_read → base64_encode → zlib_compress → requests.post
    => Score: 95
    => Level: CRITICAL
"""

from typing import Dict, Any, List, Optional

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.attack_scorer_weights import (
    SOURCE_SCORES,
    TRANSFORM_SCORES,
    SINK_SCORES,
    THRESHOLDS,
    COMPLEXITY_BONUSES,
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _get_source_score(source: str) -> int:
    """
    Get score for a source type.
    """
    # Normalize source names
    if source.startswith("env_"):
        source = "env_var"
    return SOURCE_SCORES.get(source, 10)


def _get_transform_score(transform: str) -> int:
    """
    Get score for a transform type.
    """
    return TRANSFORM_SCORES.get(transform, 10)


def _get_sink_score(sink: str) -> int:
    """
    Get score for a sink type.
    """
    return SINK_SCORES.get(sink, 10)


def _get_complexity_bonus(transform_count: int) -> int:
    """
    Get complexity bonus based on number of transforms.
    """
    if transform_count >= 6:
        return COMPLEXITY_BONUSES.get(6, 25)
    elif transform_count >= 4:
        return COMPLEXITY_BONUSES.get(4, 20)
    elif transform_count >= 2:
        return COMPLEXITY_BONUSES.get(2, 15)
    return 0


def _get_level(score: int) -> str:
    """
    Get threat level based on numeric score.
    
    Args:
        score: Numeric score (0-100)
        
    Returns:
        Threat level string
    """
    if score >= THRESHOLDS.get("CRITICAL", 90):
        return "CRITICAL"
    if score >= THRESHOLDS.get("HIGH", 70):
        return "HIGH"
    if score >= THRESHOLDS.get("MEDIUM", 40):
        return "MEDIUM"
    return "LOW"


def _clamp_score(score: int) -> int:
    """
    Clamp score between 0 and 100.
    """
    return max(0, min(score, 100))


# ==========================================
# SCORER CLASS
# ==========================================

class AttackScorer:
    """
    Attack scoring engine for assessing threat levels.
    
    Scores are calculated based on:
        - Source weight (where data originates)
        - Transform weights (what operations are applied)
        - Sink weight (where data ends up)
        - Complexity bonus (number of transforms)
    """

    def __init__(self):
        """Initialize the scorer with default weights."""
        self.source_scores = SOURCE_SCORES.copy()
        self.transform_scores = TRANSFORM_SCORES.copy()
        self.sink_scores = SINK_SCORES.copy()

    # ======================================
    # THREAT LEVEL
    # ======================================

    @staticmethod
    def get_level(score: int) -> str:
        """
        Get threat level based on numeric score.
        
        Args:
            score: Numeric score (0-100)
            
        Returns:
            Threat level string
        """
        return _get_level(score)

    # ======================================
    # FLOW SCORING
    # ======================================

    def score_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a single data flow.
        
        Args:
            flow: Flow dictionary with source, transforms, sink
            
        Returns:
            Scored flow with score and level
        """
        source = flow.get("source", "unknown")
        transforms = flow.get("transforms", [])
        sink = flow.get("sink", "unknown")
        
        # Calculate score
        score = 0
        score += _get_source_score(source)
        score += sum(_get_transform_score(t) for t in transforms)
        score += _get_sink_score(sink)
        score += _get_complexity_bonus(len(transforms))
        
        # Clamp and get level
        score = _clamp_score(score)
        
        return {
            "score": score,
            "level": _get_level(score),
            "source": source,
            "sink": sink,
            "transforms": transforms,
            "transform_count": len(transforms),
        }

    # ======================================
    # MULTIPLE FLOWS
    # ======================================

    def score_all(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Score multiple data flows.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            List of scored flows
        """
        return [self.score_flow(flow) for flow in flows]


# ==========================================
# FUNCTIONAL API
# ==========================================

def score_attacks(
    attacks: List[Dict[str, Any]],
    feature_vector: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Score attack findings for scan.py compatibility.
    
    Args:
        attacks: List of attack findings
        feature_vector: Behavioral feature vector (optional)
        
    Returns:
        List of attacks with scores added
    """
    if not attacks:
        return []
    
    scorer = AttackScorer()
    scored_attacks = []
    
    for attack in attacks:
        evidence = attack.get("evidence", {})
        
        # Extract flow from evidence
        flow = {
            "source": evidence.get("source", "unknown"),
            "transforms": evidence.get("transforms", []),
            "sink": evidence.get("sink", "unknown"),
        }
        
        # If evidence is a dict with behaviors, try to extract source
        if "matched_behaviors" in evidence:
            # For behavior-based attacks, use the attack type to determine flow
            attack_type = attack.get("attack_type", "")
            if "CREDENTIAL" in attack_type:
                flow["source"] = "credential"
                flow["sink"] = "network"
            elif "EXFILTRATION" in attack_type:
                flow["source"] = "file_read"
                flow["sink"] = "network"
        
        # Score the flow
        scored_flow = scorer.score_flow(flow)
        
        # Add score to attack
        attack_copy = attack.copy()
        attack_copy["score"] = scored_flow["score"]
        attack_copy["level"] = scored_flow["level"]
        attack_copy["flow_score"] = scored_flow
        
        scored_attacks.append(attack_copy)
    
    return scored_attacks


def score_attack(attack: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score a single attack (legacy compatibility).
    
    Args:
        attack: Attack dictionary
        
    Returns:
        Attack with score added
    """
    scorer = AttackScorer()
    evidence = attack.get("evidence", {})
    
    flow = {
        "source": evidence.get("source", "unknown"),
        "transforms": evidence.get("transforms", []),
        "sink": evidence.get("sink", "unknown"),
    }
    
    scored = scorer.score_flow(flow)
    
    attack_copy = attack.copy()
    attack_copy["score"] = scored["score"]
    attack_copy["level"] = scored["level"]
    
    return attack_copy


def get_attack_metrics(scored_attacks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get aggregate metrics from scored attacks.
    
    Args:
        scored_attacks: List of scored attacks
        
    Returns:
        Metrics dictionary with averages and counts
    """
    if not scored_attacks:
        return {
            "total": 0,
            "avg_score": 0,
            "max_score": 0,
            "levels": {},
        }
    
    total_score = 0
    max_score = 0
    levels = {}
    
    for attack in scored_attacks:
        score = attack.get("score", 0)
        total_score += score
        max_score = max(max_score, score)
        
        level = attack.get("level", "UNKNOWN")
        levels[level] = levels.get(level, 0) + 1
    
    return {
        "total": len(scored_attacks),
        "avg_score": round(total_score / len(scored_attacks), 2),
        "max_score": max_score,
        "levels": levels,
    }


# ==========================================
# LEGACY SUPPORT
# ==========================================

def score_attacks_legacy(
    attacks: List[Dict[str, Any]],
    feature_vector: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return score_attacks(attacks, feature_vector)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "AttackScorer",
    "score_attacks",
    "score_attacks_legacy",
    "score_attack",
    "get_attack_metrics",
    "SOURCE_SCORES",
    "TRANSFORM_SCORES",
    "SINK_SCORES",
]