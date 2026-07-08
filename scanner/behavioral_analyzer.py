"""
behavioral_analyzer.py
----------------------
Merges behavioral_extractor (feature vector filling)
with source_sink_tracker (alias-aware data flow).
Returns feature_vector + data_flows for downstream modules.

This is the main orchestration point for Phase 2 analysis.
"""

import ast
from typing import Dict, Any, Optional, List, Set, Tuple

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.behavior_mappings import (
    NETWORK_CALLS,
    PROCESS_CALLS,
    RECON_CALLS,
    OBFUSCATION_CALLS,
    ANTI_FORENSICS_CALLS,
    PERSISTENCE_CALLS,
    EVAL_EXEC_CALLS,
)
from scanner.data.sensitive_sources import SUSPICIOUS_ENV

# ==========================================
# MODULE IMPORTS
# ==========================================

from scanner.behavioral_extractor import extract_behavior
from scanner.source_sink_tracker import analyze_data_flow, get_call_name
from scanner.feature_vector import create_feature_vector, add_data_flow_path


# ==========================================
# CONSTANTS
# ==========================================

# Types of data flow paths we can detect
FLOW_PATH_TYPES = {
    "FILE_TO_NETWORK": "file_to_network_exfiltration",
    "FILE_TO_NETWORK_WITH_TRANSFORMS": "file_to_network_obfuscated_exfiltration",
    "CREDENTIAL_TO_NETWORK": "credential_to_network_exfiltration",
    "ENV_TO_NETWORK": "env_to_network_exfiltration",
}


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _get_forensic_keywords() -> Set[str]:
    """
    Lazy import to avoid circular dependency.
    
    Returns:
        Set of forensic target keywords
    """
    try:
        from scanner.data.forensic_artifacts import FORENSIC_TARGET_KEYWORDS
        return FORENSIC_TARGET_KEYWORDS
    except ImportError:
        # Fallback if the module doesn't exist
        return {
            "history", "bash_history", ".bash_history", "syslog", "auth.log",
            "eventlog", "wtmp", "btmp", "lastlog", "audit", "prefetch",
        }


def _contains_forensic_target(node: ast.AST) -> bool:
    """
    Check if an AST node contains forensic target keywords.
    
    Args:
        node (ast.AST): AST node to check
        
    Returns:
        bool: True if forensic target found
    """
    try:
        text = ast.unparse(node).lower()
        keywords = _get_forensic_keywords()
        return any(k in text for k in keywords)
    except Exception:
        return False


def _enrich_feature_vector_with_flows(
    feature_vector: Dict[str, Any],
    flows: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Enrich the feature vector with findings from data flows.
    
    Args:
        feature_vector: Current feature vector
        flows: List of data flows
        
    Returns:
        Updated feature vector
    """
    for flow in flows:
        source_type = flow.get("source", "").lower()
        sink_type = flow.get("sink", "").lower()
        transforms = flow.get("transforms", [])
        
        # File read detection
        if "file" in source_type:
            feature_vector["file_read"] = True
        
        # Network request detection
        if "network" in sink_type or "requests" in sink_type or "socket" in sink_type:
            feature_vector["network_request"] = True
        
        # Obfuscation detection
        if transforms:
            feature_vector["obfuscation"] = True
        
        # File to network exfiltration pattern
        if "file" in source_type and "network" in sink_type:
            if transforms:
                add_data_flow_path(
                    feature_vector,
                    FLOW_PATH_TYPES["FILE_TO_NETWORK_WITH_TRANSFORMS"]
                )
            else:
                add_data_flow_path(
                    feature_vector,
                    FLOW_PATH_TYPES["FILE_TO_NETWORK"]
                )
        
        # Credential to network exfiltration
        if "credential" in source_type or "env" in source_type:
            if "network" in sink_type or "requests" in sink_type:
                if "credential" in source_type:
                    add_data_flow_path(
                        feature_vector,
                        FLOW_PATH_TYPES["CREDENTIAL_TO_NETWORK"]
                    )
                else:
                    add_data_flow_path(
                        feature_vector,
                        FLOW_PATH_TYPES["ENV_TO_NETWORK"]
                    )
    
    return feature_vector


def _get_tainted_variables(flows: List[Dict[str, Any]]) -> List[str]:
    """
    Extract tainted variable names from flows.
    
    Args:
        flows: List of data flows
        
    Returns:
        List of tainted variable names
    """
    tainted = []
    for flow in flows:
        source_var = flow.get("source_var", "")
        if source_var and source_var not in tainted:
            tainted.append(source_var)
    return tainted


# ==========================================
# MAIN ANALYSIS FUNCTION
# ==========================================

def analyze_behavior(
    tree: ast.AST,
    source: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyze code behavior by combining feature extraction with data flow analysis.
    
    Args:
        tree (ast.AST): Parsed AST of the code
        source (str, optional): Source code string (kept for backward compatibility)
        
    Returns:
        dict: Contains:
            - feature_vector: Dict of boolean behavioral flags
            - data_flows: List of source->transform->sink flow dicts
            - tainted_vars: Variable names carrying sensitive data
    """
    # Phase 1: Extract features using the dedicated extractor
    feature_vector = extract_behavior(tree)
    
    # Phase 2: Add data flow tracking via SourceSinkTracker
    flows = analyze_data_flow(tree)
    
    # Phase 3: Enrich feature vector with flow findings
    feature_vector = _enrich_feature_vector_with_flows(feature_vector, flows)
    
    # Phase 4: Extract tainted variables
    tainted_vars = _get_tainted_variables(flows)
    
    return {
        "feature_vector": feature_vector,
        "data_flows": flows,
        "tainted_vars": tainted_vars,
    }


# ==========================================
# LEGACY SUPPORT
# ==========================================

def analyze_behavior_legacy(
    tree: ast.AST,
    source: str = ""
) -> Dict[str, Any]:
    """
    Legacy wrapper for backward compatibility.
    """
    return analyze_behavior(tree, source)


# ==========================================
# HELPER: GET SUMMARY
# ==========================================

def get_behavior_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get a summary of behavioral analysis results.
    
    Args:
        result: Result from analyze_behavior()
        
    Returns:
        Summary dictionary
    """
    feature_vector = result.get("feature_vector", {})
    flows = result.get("data_flows", [])
    tainted_vars = result.get("tainted_vars", [])
    
    # Count enabled features
    enabled_features = [
        key for key, value in feature_vector.items()
        if value is True and key != "data_flow_paths"
    ]
    
    return {
        "total_features": len(feature_vector),
        "enabled_features": len(enabled_features),
        "enabled_feature_list": enabled_features,
        "total_flows": len(flows),
        "tainted_vars": len(tainted_vars),
        "data_flow_paths": feature_vector.get("data_flow_paths", []),
    }


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "analyze_behavior",
    "analyze_behavior_legacy",
    "get_behavior_summary",
    "FLOW_PATH_TYPES",
]