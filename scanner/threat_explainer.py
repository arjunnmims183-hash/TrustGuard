"""
threat_explainer.py
-------------------
Converts source -> transform -> sink flows into analyst-readable explanations.
Generates explanations for detected threats.

All descriptions and explanations are loaded from data files.
"""

from typing import Dict, Any, List, Optional, Tuple

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.source_descriptions import (
    SOURCE_DESCRIPTIONS,
    get_source_description,
)
from scanner.data.transform_descriptions import (
    TRANSFORM_DESCRIPTIONS,
    get_transform_description,
)
from scanner.data.sink_descriptions import (
    SINK_DESCRIPTIONS,
    get_sink_description,
)
from scanner.data.attack_explanations import (
    ATTACK_EXPLANATIONS,
    DEFAULT_EXPLANATION,
    get_attack_explanation,
    format_explanation,
)


# ==========================================
# CONSTANTS
# ==========================================

# Source types that indicate specific threat patterns
THREAT_PATTERNS = {
    "file_read": {
        "with_transforms": "obfuscated data exfiltration pattern",
        "without_transforms": "direct data exfiltration pattern",
    },
    "env_var": {
        "with_transforms": "credential theft with obfuscation",
        "without_transforms": "credential theft",
    },
    "credential": {
        "with_transforms": "credential theft with obfuscation",
        "without_transforms": "credential theft",
    },
    "user_input": {
        "description": "user input collection and transmission",
    },
    "network_recv": {
        "description": "data received from a remote source is being retransmitted",
    },
}


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _get_threat_interpretation(source: str, has_transforms: bool) -> str:
    """
    Get threat interpretation based on source and transform presence.
    
    Args:
        source: Source type
        has_transforms: Whether transforms are present
        
    Returns:
        Threat interpretation string
    """
    pattern = THREAT_PATTERNS.get(source)
    if not pattern:
        return ""
    
    if "with_transforms" in pattern and "without_transforms" in pattern:
        if has_transforms:
            return pattern["with_transforms"]
        return pattern["without_transforms"]
    
    return pattern.get("description", "")


def _build_flow_summary(
    source: str,
    sink: str,
    transform_count: int
) -> str:
    """
    Build the summary for a flow explanation.
    
    Args:
        source: Source type
        sink: Sink type
        transform_count: Number of transforms
        
    Returns:
        Summary string
    """
    return (
        f"Data originating from '{source}' "
        f"was transformed {transform_count} time(s) before "
        f"reaching '{sink}'."
    )


def _build_flow_details(
    source: str,
    transforms: List[str],
    sink: str
) -> List[str]:
    """
    Build the details list for a flow explanation.
    
    Args:
        source: Source type
        transforms: List of transforms
        sink: Sink type
        
    Returns:
        List of detail strings
    """
    details = []
    
    # Source description
    details.append(get_source_description(source))
    
    # Transform descriptions
    for transform in transforms:
        details.append(get_transform_description(transform))
    
    # Sink description
    details.append(get_sink_description(sink))
    
    return details


# ==========================================
# FLOW EXPLANATION
# ==========================================

def explain_flow(flow: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate explanation for a single data flow.
    
    Args:
        flow: Data flow dictionary with source, sink, transforms
        
    Returns:
        Dictionary with summary and details
    """
    source = flow.get("source", "unknown")
    sink = flow.get("sink", "unknown")
    transforms = flow.get("transforms", [])
    transform_count = len(transforms)
    
    # Build summary
    summary = _build_flow_summary(source, sink, transform_count)
    
    # Add threat interpretation
    interpretation = _get_threat_interpretation(source, transform_count > 0)
    if interpretation:
        summary += f" This resembles {interpretation}."
    
    # Build details
    details = _build_flow_details(source, transforms, sink)
    
    return {
        "summary": summary,
        "details": details,
        "source": source,
        "sink": sink,
        "transform_count": transform_count,
    }


# ==========================================
# THREAT EXPLANATION (For scan.py)
# ==========================================

def explain_threats(
    findings: List[Dict[str, Any]],
    feature_vector: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Generate explanations for detected threats.
    
    Args:
        findings: List of attack findings
        feature_vector: Behavioral feature vector (optional)
        
    Returns:
        List of findings with explanations added
    """
    if not findings:
        return []
    
    explained = []
    for finding in findings:
        attack_type = finding.get("attack_type", "")
        
        # Get template for this attack type
        template = get_attack_explanation(attack_type)
        
        # Add explanation to finding
        finding_copy = finding.copy()
        finding_copy["explanation"] = template
        
        # Add flow explanation if evidence is a flow
        evidence = finding.get("evidence", {})
        if isinstance(evidence, dict) and "source" in evidence:
            flow_explanation = explain_flow(evidence)
            finding_copy["flow_explanation"] = flow_explanation
        
        # Add behavioral context if feature vector provided
        if feature_vector:
            behavioral_context = _get_behavioral_context(feature_vector)
            if behavioral_context:
                finding_copy["behavioral_context"] = behavioral_context
        
        explained.append(finding_copy)
    
    return explained


def _get_behavioral_context(feature_vector: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract behavioral context from feature vector.
    
    Args:
        feature_vector: Behavioral feature vector
        
    Returns:
        Dictionary with behavioral context
    """
    context = {}
    
    # Key behaviors to highlight
    key_behaviors = [
        "credential_access",
        "obfuscation",
        "anti_forensics",
        "persistence_attempt",
        "system_recon",
        "subprocess",
    ]
    
    enabled = []
    for behavior in key_behaviors:
        if feature_vector.get(behavior, False):
            enabled.append(behavior)
    
    if enabled:
        context["enabled_behaviors"] = enabled
    
    # Data flow paths
    flow_paths = feature_vector.get("data_flow_paths", [])
    if flow_paths:
        context["data_flow_paths"] = flow_paths
    
    return context


# ==========================================
# SINGLE ATTACK EXPLANATION
# ==========================================

def explain_attack(
    attack_type: str,
    evidence: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate explanation for a single attack.
    
    Args:
        attack_type: Type of attack
        evidence: Evidence dictionary
        
    Returns:
        Dictionary with explanation
    """
    template = get_attack_explanation(attack_type)
    result = template.copy()
    
    # Add flow explanation if available
    if "source" in evidence:
        flow_explanation = explain_flow(evidence)
        result["flow_summary"] = flow_explanation["summary"]
        result["flow_details"] = flow_explanation["details"]
    
    return result


# ==========================================
# QUERY FUNCTIONS
# ==========================================

def get_explanation(attack_type: str) -> Dict[str, str]:
    """
    Get explanation template for an attack type.
    
    Args:
        attack_type: Type of attack
        
    Returns:
        Explanation template dictionary
    """
    return get_attack_explanation(attack_type)


def get_flow_summary(flow: Dict[str, Any]) -> str:
    """
    Get just the summary for a flow.
    
    Args:
        flow: Data flow dictionary
        
    Returns:
        Summary string
    """
    return explain_flow(flow)["summary"]


def get_flow_details(flow: Dict[str, Any]) -> List[str]:
    """
    Get just the details for a flow.
    
    Args:
        flow: Data flow dictionary
        
    Returns:
        List of detail strings
    """
    return explain_flow(flow)["details"]


# ==========================================
# BATCH EXPLANATIONS
# ==========================================

def explain_flows(flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Explain multiple flows.
    
    Args:
        flows: List of data flow dictionaries
        
    Returns:
        List of flow explanations
    """
    return [explain_flow(flow) for flow in flows]


def explain_all(
    findings: List[Dict[str, Any]],
    flows: List[Dict[str, Any]],
    feature_vector: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate explanations for both findings and flows.
    
    Args:
        findings: List of attack findings
        flows: List of data flows
        feature_vector: Behavioral feature vector
        
    Returns:
        Dictionary with explained findings and flows
    """
    return {
        "explained_findings": explain_threats(findings, feature_vector),
        "explained_flows": explain_flows(flows),
    }


# ==========================================
# BACKWARD COMPATIBILITY
# ==========================================

def explain_threats_legacy(
    findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return explain_threats(findings)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "explain_flow",
    "explain_flows",
    "explain_threats",
    "explain_threats_legacy",
    "explain_attack",
    "explain_all",
    "get_explanation",
    "get_flow_summary",
    "get_flow_details",
    "format_explanation",
]