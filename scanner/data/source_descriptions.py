"""
source_descriptions.py
----------------------
Human-readable descriptions for data sources.
"""

from typing import Dict, List

SOURCE_DESCRIPTIONS: Dict[str, str] = {
    "file_read": "Reads data from a local file.",
    "env_var": "Reads information from environment variables.",
    "credential": "Collects credentials from the user.",
    "user_input": "Collects user supplied input.",
    "network_recv": "Receives data from a remote source.",
    "unknown": "Unknown data source.",
}


def get_source_description(source: str) -> str:
    """Get description for a source type."""
    return SOURCE_DESCRIPTIONS.get(source, f"Source detected: {source}")


def get_all_source_types() -> List[str]:
    """Get all available source types."""
    return list(SOURCE_DESCRIPTIONS.keys())


__all__ = [
    "SOURCE_DESCRIPTIONS",
    "get_source_description",
    "get_all_source_types",
]