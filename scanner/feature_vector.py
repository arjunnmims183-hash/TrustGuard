"""
feature_vector.py
-----------------
Defines the behavioral feature vector schema for TrustGuard.
This is the central data structure used throughout the pipeline.

The feature vector tracks boolean indicators of suspicious/malicious behaviors:
    - File operations (read/write)
    - Network operations (request/receive)
    - Process execution
    - Dynamic code execution (eval/exec)
    - Obfuscation techniques
    - Persistence mechanisms
    - Credential access
    - System reconnaissance
    - Anti-forensics techniques
    - Data flow paths (for correlation)
"""

from typing import Dict, Any, List, Set


# ==========================================
# FEATURE SCHEMA
# ==========================================

FEATURE_SCHEMA: Dict[str, Any] = {
    # File operations
    "file_read": False,
    "file_write": False,
    "file_deletion": False,  # Added for completeness
    
    # Network operations
    "network_request": False,
    "network_recv": False,
    
    # Process execution
    "subprocess": False,
    
    # Dynamic code execution
    "eval_usage": False,
    "exec_usage": False,
    
    # Obfuscation
    "obfuscation": False,
    
    # Persistence
    "persistence_attempt": False,
    
    # Credential access
    "credential_access": False,
    
    # Reconnaissance
    "system_recon": False,
    
    # Anti-forensics
    "anti_forensics": False,
    
    # Data flow paths (list of detected flow types)
    "data_flow_paths": [],  # List[str]
}

# ==========================================
# FEATURE CATEGORIES (for grouping in reports)
# ==========================================

FEATURE_CATEGORIES: Dict[str, List[str]] = {
    "File Operations": ["file_read", "file_write", "file_deletion"],
    "Network": ["network_request", "network_recv"],
    "Execution": ["subprocess", "eval_usage", "exec_usage"],
    "Security": ["obfuscation", "persistence_attempt", "credential_access", "anti_forensics"],
    "Reconnaissance": ["system_recon"],
    "Data Flow": ["data_flow_paths"],
}

# ==========================================
# FEATURE DESCRIPTIONS (for reports)
# ==========================================

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "file_read": "Reads data from files",
    "file_write": "Writes data to files",
    "file_deletion": "Deletes files (anti-forensic)",
    "network_request": "Makes network requests (outbound)",
    "network_recv": "Receives network data (inbound)",
    "subprocess": "Executes subprocesses or system commands",
    "eval_usage": "Uses eval() for dynamic code execution",
    "exec_usage": "Uses exec() for dynamic code execution",
    "obfuscation": "Uses obfuscation techniques (encoding/compression)",
    "persistence_attempt": "Attempts to establish persistence",
    "credential_access": "Accesses credentials or secrets",
    "system_recon": "Performs system reconnaissance",
    "anti_forensics": "Uses anti-forensic techniques",
}


# ==========================================
# MAIN FUNCTIONS
# ==========================================

def create_feature_vector() -> Dict[str, Any]:
    """
    Create a new feature vector with all features initialized to False.
    
    Returns:
        Dict[str, Any]: Feature vector with default values
    """
    return {
        "file_read": False,
        "file_write": False,
        "file_deletion": False,
        "network_request": False,
        "network_recv": False,
        "subprocess": False,
        "eval_usage": False,
        "exec_usage": False,
        "obfuscation": False,
        "persistence_attempt": False,
        "credential_access": False,
        "system_recon": False,
        "anti_forensics": False,
        "data_flow_paths": [],
    }


def is_feature_true(feature_vector: Dict[str, Any], feature_name: str) -> bool:
    """
    Check if a specific feature is True in the feature vector.
    
    Args:
        feature_vector: The feature vector dictionary
        feature_name: Name of the feature to check
        
    Returns:
        bool: True if feature is enabled, False otherwise
    """
    return feature_vector.get(feature_name, False) is True


def get_enabled_features(feature_vector: Dict[str, Any]) -> List[str]:
    """
    Get a list of all features that are enabled (True).
    
    Args:
        feature_vector: The feature vector dictionary
        
    Returns:
        List[str]: Names of enabled features
    """
    return [
        key for key, value in feature_vector.items()
        if value is True and key != "data_flow_paths"
    ]


def get_enabled_features_by_category(feature_vector: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Get enabled features grouped by category.
    
    Args:
        feature_vector: The feature vector dictionary
        
    Returns:
        Dict[str, List[str]]: Category -> list of enabled features
    """
    enabled = set(get_enabled_features(feature_vector))
    
    result = {}
    for category, features in FEATURE_CATEGORIES.items():
        enabled_in_category = [f for f in features if f in enabled]
        if enabled_in_category:
            result[category] = enabled_in_category
    
    return result


def get_feature_count(feature_vector: Dict[str, Any]) -> int:
    """
    Get the number of enabled features (excluding data_flow_paths).
    
    Args:
        feature_vector: The feature vector dictionary
        
    Returns:
        int: Number of enabled features
    """
    return len(get_enabled_features(feature_vector))


def add_data_flow_path(feature_vector: Dict[str, Any], path: str) -> None:
    """
    Add a data flow path to the feature vector (deduplicated).
    
    Args:
        feature_vector: The feature vector dictionary
        path: Data flow path string to add
    """
    if "data_flow_paths" not in feature_vector:
        feature_vector["data_flow_paths"] = []
    
    if path not in feature_vector["data_flow_paths"]:
        feature_vector["data_flow_paths"].append(path)


def get_data_flow_paths(feature_vector: Dict[str, Any]) -> List[str]:
    """
    Get all data flow paths from the feature vector.
    
    Args:
        feature_vector: The feature vector dictionary
        
    Returns:
        List[str]: Data flow paths
    """
    return feature_vector.get("data_flow_paths", [])


def merge_feature_vectors(feature_vectors: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge multiple feature vectors into one (OR operation on booleans).
    
    Args:
        feature_vectors: List of feature vector dictionaries
        
    Returns:
        Dict[str, Any]: Merged feature vector
    """
    if not feature_vectors:
        return create_feature_vector()
    
    merged = create_feature_vector()
    
    for fv in feature_vectors:
        for key, value in fv.items():
            if key == "data_flow_paths":
                # Merge data flow paths
                for path in value:
                    add_data_flow_path(merged, path)
            elif isinstance(value, bool):
                # OR operation on booleans
                if value:
                    merged[key] = True
    
    return merged


# ==========================================
# LEGACY SUPPORT
# ==========================================

def create_feature_vector_legacy() -> Dict[str, Any]:
    """
    Legacy wrapper for backward compatibility.
    """
    return create_feature_vector()


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "create_feature_vector",
    "create_feature_vector_legacy",
    "is_feature_true",
    "get_enabled_features",
    "get_enabled_features_by_category",
    "get_feature_count",
    "add_data_flow_path",
    "get_data_flow_paths",
    "merge_feature_vectors",
    "FEATURE_SCHEMA",
    "FEATURE_CATEGORIES",
    "FEATURE_DESCRIPTIONS",
]