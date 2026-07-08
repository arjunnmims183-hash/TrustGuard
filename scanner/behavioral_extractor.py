"""
behavioral_extractor.py
------------------------
Extracts behavioral features from Python AST for threat analysis.
Uses centralized behavior mappings from scanner.data.behavior_mappings.

This module walks the AST and sets boolean flags in the feature vector
based on detected API calls, patterns, and behaviors.
"""

import ast
from typing import Dict, Any, Optional, List, Set, Callable

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.behavior_mappings import (
    NETWORK_CALLS,
    NETWORK_RECEIVE_CALLS,
    PROCESS_CALLS,
    FILE_READ_CALLS,
    FILE_WRITE_CALLS,
    FILE_DELETE_CALLS,
    EVAL_EXEC_CALLS,
    OBFUSCATION_CALLS,
    RECON_CALLS,
    PERSISTENCE_CALLS,
    CREDENTIAL_ACCESS_CALLS,
    ANTI_FORENSICS_CALLS,
)
from scanner.data.sensitive_sources import SUSPICIOUS_ENV
from scanner.data.forensic_artifacts import FORENSIC_TARGET_KEYWORDS

# ==========================================
# MODULE IMPORTS
# ==========================================

from scanner.feature_vector import create_feature_vector, add_data_flow_path


# ==========================================
# CONSTANTS
# ==========================================

# Data flow path types
DATA_FLOW_PATHS = {
    "FORENSIC_ARTIFACT_CLEANUP": "forensic_artifact_cleanup",
    "SENSITIVE_ENV_VAR_ACCESS": "sensitive_env_var_access",
}

# Special call patterns that need extra handling
ENV_ACCESS_CALLS = {"os.getenv", "os.environ.get"}


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def get_call_name(node: ast.AST) -> Optional[str]:
    """
    Get fully qualified name of a function call node.
    
    Handles:
        - Simple names: eval, open
        - Attributes: requests.post, os.getenv
        - Nested calls: pathlib.Path.read_text()
    
    Args:
        node (ast.AST): AST node (should be ast.Call, ast.Name, or ast.Attribute)
        
    Returns:
        str or None: Fully qualified name like "requests.get"
    """
    if isinstance(node, ast.Name):
        return node.id
    
    elif isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    
    elif isinstance(node, ast.Call):
        return get_call_name(node.func)
    
    return None


def contains_forensic_target(node: ast.AST) -> bool:
    """
    Check if an AST node contains forensic target keywords.
    
    Args:
        node (ast.AST): AST node to check
        
    Returns:
        bool: True if forensic target found
    """
    try:
        target_text = ast.unparse(node).lower()
        return any(
            keyword in target_text
            for keyword in FORENSIC_TARGET_KEYWORDS
        )
    except Exception:
        return False


def _get_open_mode(node: ast.Call) -> Optional[str]:
    """
    Extract the mode from an open() call.
    
    Args:
        node: AST Call node for open()
        
    Returns:
        Mode string or None if not specified
    """
    if len(node.args) < 2:
        return None
    if isinstance(node.args[1], ast.Constant):
        return str(node.args[1].value)
    return None


def _is_read_mode(mode: Optional[str]) -> bool:
    """Check if the mode is a read mode."""
    if mode is None:
        return True
    return "r" in mode


def _is_write_mode(mode: Optional[str]) -> bool:
    """Check if the mode is a write/append mode."""
    if mode is None:
        return False
    return any(c in mode for c in ("w", "a", "+", "x"))


def _handle_open_call(node: ast.Call, features: Dict[str, Any]) -> None:
    """
    Handle open() calls to set read/write flags.
    """
    mode = _get_open_mode(node)
    if _is_read_mode(mode):
        features["file_read"] = True
    if _is_write_mode(mode):
        features["file_write"] = True


def _handle_env_access(node: ast.Call, features: Dict[str, Any]) -> None:
    """
    Handle environment variable access calls.
    """
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return
    
    env_name = str(node.args[0].value).upper()
    for keyword in SUSPICIOUS_ENV:
        if keyword in env_name:
            features["credential_access"] = True
            add_data_flow_path(features, DATA_FLOW_PATHS["SENSITIVE_ENV_VAR_ACCESS"])
            break


def _handle_anti_forensics(node: ast.Call, call_name: str, features: Dict[str, Any]) -> None:
    """
    Handle anti-forensics detection.
    """
    features["anti_forensics"] = True
    
    # Track file deletion specifically
    if call_name in FILE_DELETE_CALLS:
        features["file_deletion"] = True
    
    # Check for forensic artifact cleanup
    if node.args and contains_forensic_target(node.args[0]):
        add_data_flow_path(features, DATA_FLOW_PATHS["FORENSIC_ARTIFACT_CLEANUP"])


# ==========================================
# MAIN EXTRACTION FUNCTION
# ==========================================

def extract_behavior(
    tree: ast.AST,
    source: Optional[str] = None
) -> Dict[str, Any]:
    """
    Extract behavioral features from AST.
    
    Args:
        tree (ast.AST): Parsed AST of the code
        source (str, optional): Source code string (kept for backward compatibility)
        
    Returns:
        dict: Feature vector with behavioral indicators
    """
    features = create_feature_vector()
    
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
            
        call_name = get_call_name(node.func)
        
        # =====================================
        # FILE ACTIVITY - Standard open()
        # =====================================
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            _handle_open_call(node, features)
        
        # =====================================
        # FILE ACTIVITY - Pathlib and other APIs
        # =====================================
        if call_name in FILE_READ_CALLS:
            features["file_read"] = True
            
        if call_name in FILE_WRITE_CALLS:
            features["file_write"] = True
        
        # =====================================
        # NETWORK ACTIVITY
        # =====================================
        if call_name in NETWORK_CALLS:
            features["network_request"] = True
            
        # =====================================
        # NETWORK RECEIVE
        # =====================================
        if call_name in NETWORK_RECEIVE_CALLS:
            features["network_recv"] = True
            
        # =====================================
        # PROCESS EXECUTION
        # =====================================
        if call_name in PROCESS_CALLS:
            features["subprocess"] = True
            
        # =====================================
        # SYSTEM RECON
        # =====================================
        if call_name in RECON_CALLS:
            features["system_recon"] = True
            
        # =====================================
        # ANTI-FORENSICS
        # =====================================
        if call_name in ANTI_FORENSICS_CALLS:
            _handle_anti_forensics(node, call_name, features)
        
        # =====================================
        # CREDENTIAL ACCESS
        # =====================================
        # Generic credential API detection
        if call_name in CREDENTIAL_ACCESS_CALLS:
            features["credential_access"] = True
        
        # Special env-variable inspection with extra detail
        if call_name in ENV_ACCESS_CALLS:
            _handle_env_access(node, features)
        
        # =====================================
        # OBFUSCATION
        # =====================================
        if call_name in OBFUSCATION_CALLS:
            features["obfuscation"] = True
            
        # =====================================
        # EVAL/EXEC
        # =====================================
        if call_name in EVAL_EXEC_CALLS:
            features["eval_usage"] = True
            
        # =====================================
        # PERSISTENCE
        # =====================================
        if call_name in PERSISTENCE_CALLS:
            features["persistence_attempt"] = True
    
    return features


# ==========================================
# LEGACY SUPPORT
# ==========================================

def extract_behavior_legacy(
    tree: ast.AST,
    source: str = ""
) -> Dict[str, Any]:
    """
    Legacy wrapper for backward compatibility.
    Delegates to the refactored extract_behavior.
    
    Args:
        tree (ast.AST): Parsed AST
        source (str): Source code (unused, kept for compatibility)
        
    Returns:
        dict: Feature vector
    """
    return extract_behavior(tree)


# ==========================================
# HELPER: GET EXTRACTION SUMMARY
# ==========================================

def get_extraction_summary(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get a summary of extracted features.
    
    Args:
        features: Feature vector from extract_behavior()
        
    Returns:
        Summary dictionary
    """
    enabled = [
        key for key, value in features.items()
        if value is True and key != "data_flow_paths"
    ]
    
    return {
        "total_features": len(features),
        "enabled_features": len(enabled),
        "enabled_list": enabled,
        "data_flow_paths": features.get("data_flow_paths", []),
        "is_suspicious": len(enabled) > 0,
    }


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "extract_behavior",
    "extract_behavior_legacy",
    "get_call_name",
    "contains_forensic_target",
    "get_extraction_summary",
    "DATA_FLOW_PATHS",
]