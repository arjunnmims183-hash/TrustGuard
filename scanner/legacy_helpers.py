"""
legacy_helpers.py
-----------------
Helper functions for migrating from flat keys to structured format.

These functions handle both formats, making it easier to update modules
gradually without breaking everything at once.

DEPRECATED: These will be removed in v4.0 after all modules are migrated.
"""

from typing import Dict, Any, List, Optional


def get_phase1(result: Dict[str, Any], key: str, default=None) -> Any:
    """
    Get a Phase 1 value, trying structured format first, then flat keys.
    
    Args:
        result: The scan result dictionary
        key: The key to retrieve (e.g., 'dangerous_apis')
        default: Default value if not found
        
    Returns:
        The value from structured or flat format
    """
    # Try structured format
    phase1 = result.get("phase1", {})
    if key in phase1:
        return phase1[key]
    
    # Fallback to flat keys
    return result.get(key, default)


def get_phase2(result: Dict[str, Any], key: str, default=None) -> Any:
    """
    Get a Phase 2 value, trying structured format first, then flat keys.
    
    Args:
        result: The scan result dictionary
        key: The key to retrieve (e.g., 'feature_vector')
        default: Default value if not found
        
    Returns:
        The value from structured or flat format
    """
    # Try structured format
    phase2 = result.get("phase2", {})
    if key in phase2:
        return phase2[key]
    
    # Fallback to flat keys
    return result.get(key, default)


def get_phase3(result: Dict[str, Any], key: str, default=None) -> Any:
    """
    Get a Phase 3 value, trying structured format first, then flat keys.
    
    Args:
        result: The scan result dictionary
        key: The key to retrieve (e.g., 'correlation_findings')
        default: Default value if not found
        
    Returns:
        The value from structured or flat format
    """
    # Try structured format
    phase3 = result.get("phase3", {})
    if key in phase3:
        return phase3[key]
    
    # Fallback to flat keys
    return result.get(key, default)


def get_dangerous_apis(result: Dict[str, Any]) -> List[str]:
    """Get dangerous APIs from result (handles both formats)."""
    return get_phase1(result, "dangerous_apis", [])


def get_secrets(result: Dict[str, Any]) -> List[str]:
    """Get secrets from result (handles both formats)."""
    return get_phase1(result, "secrets", [])


def get_vulnerabilities(result: Dict[str, Any]) -> List[str]:
    """Get vulnerabilities from result (handles both formats)."""
    return get_phase1(result, "vulnerabilities", [])


def get_feature_vector(result: Dict[str, Any]) -> Dict[str, Any]:
    """Get feature vector from result (handles both formats)."""
    return get_phase2(result, "feature_vector", {})


def get_data_flows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get data flows from result (handles both formats)."""
    return get_phase2(result, "data_flows", [])


def get_correlation_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get correlation findings from result (handles both formats)."""
    return get_phase3(result, "correlation_findings", [])


def get_mitre_mappings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get MITRE mappings from result (handles both formats)."""
    return get_phase3(result, "mitre_mappings", [])


# Export all helpers
__all__ = [
    "get_phase1",
    "get_phase2", 
    "get_phase3",
    "get_dangerous_apis",
    "get_secrets",
    "get_vulnerabilities",
    "get_feature_vector",
    "get_data_flows",
    "get_correlation_findings",
    "get_mitre_mappings",
]