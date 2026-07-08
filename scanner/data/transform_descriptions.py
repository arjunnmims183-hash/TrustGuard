"""
transform_descriptions.py
-------------------------
Human-readable descriptions for data transformations.
"""

from typing import Dict, List

TRANSFORM_DESCRIPTIONS: Dict[str, str] = {
    "encode": "Converts text into bytes.",
    "base64_encode": "Encodes data using Base64.",
    "zlib_compress": "Compresses data using ZLIB.",
    "gzip_compress": "Compresses data using GZIP.",
    "hexlify": "Converts binary data into hexadecimal.",
    "json_serialize": "Serializes data into JSON.",
    "serialize": "Serializes Python objects.",
    "pickle_serialize": "Serializes using Python pickle.",
    "encrypt": "Encrypts data.",
    "xor": "XOR encoding/encryption.",
}


def get_transform_description(transform: str) -> str:
    """Get description for a transform type."""
    return TRANSFORM_DESCRIPTIONS.get(
        transform,
        f"Transformation detected: {transform}"
    )


def get_all_transform_types() -> List[str]:
    """Get all available transform types."""
    return list(TRANSFORM_DESCRIPTIONS.keys())


__all__ = [
    "TRANSFORM_DESCRIPTIONS",
    "get_transform_description",
    "get_all_transform_types",
]