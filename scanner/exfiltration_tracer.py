"""
exfiltration_tracer.py
----------------------
Classifies data flows from source_sink_tracker into named attack chains.
"""

from typing import List, Dict, Any, Set, Optional, Tuple

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.exfiltration_rules import CHAIN_RULES, NETWORK_SINKS


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _flow_matches_rule(flow: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """
    Check if a data flow matches a chain rule.
    
    Args:
        flow: Data flow dictionary with source, sink, transforms
        rule: Chain rule dictionary with sources, sinks, requirements
        
    Returns:
        True if flow matches the rule, False otherwise
    """
    # Check source
    if flow.get("source") not in rule.get("sources", set()):
        return False
    
    # Check sink
    if flow.get("sink") not in rule.get("sinks", set()):
        return False
    
    # Check transform requirement
    if rule.get("requires_transform", False):
        if not flow.get("transforms"):
            return False
    
    return True


def _build_chain_from_flow(flow: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a chain dictionary from a flow and matching rule.
    """
    return {
        "chain_type": rule.get("name", "Unknown Chain"),
        "confidence": rule.get("confidence", "MEDIUM"),
        "description": rule.get("description", ""),
        "source_var": flow.get("source_var", "?"),
        "source_type": flow.get("source", "unknown"),
        "transforms": flow.get("transforms", []),
        "sink_call": flow.get("sink", "unknown"),
        "has_encoding": len(flow.get("transforms", [])) > 0,
    }


def _deduplicate_chains(chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate chains based on (chain_type, source_var, sink_call).
    """
    seen = set()
    unique = []
    
    for chain in chains:
        key = (
            chain.get("chain_type", ""),
            chain.get("source_var", ""),
            chain.get("sink_call", ""),
        )
        if key not in seen:
            seen.add(key)
            unique.append(chain)
    
    return unique


# ==========================================
# MAIN TRACING FUNCTION
# ==========================================

def trace_exfiltration(data_flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Trace data flows and classify them into attack chains.
    
    Args:
        data_flows: List of data flows from source_sink_tracker
        
    Returns:
        List of classified attack chains with confidence and description
    """
    if not data_flows:
        return []
    
    chains = []
    
    # Process each flow against all rules
    for flow in data_flows:
        for rule in CHAIN_RULES:
            if _flow_matches_rule(flow, rule):
                chains.append(_build_chain_from_flow(flow, rule))
    
    # Deduplicate
    return _deduplicate_chains(chains)


# ==========================================
# HELPER FUNCTIONS FOR FILTERING
# ==========================================

def filter_by_confidence(chains: List[Dict[str, Any]], min_confidence: str) -> List[Dict[str, Any]]:
    """
    Filter chains by minimum confidence level.
    
    Confidence levels: LOW < MEDIUM < HIGH < CRITICAL
    """
    levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_level = levels.get(min_confidence.upper(), 0)
    
    return [
        chain for chain in chains
        if levels.get(chain.get("confidence", "LOW").upper(), 0) >= min_level
    ]


def filter_by_source_type(chains: List[Dict[str, Any]], source_type: str) -> List[Dict[str, Any]]:
    """
    Filter chains by source type.
    """
    return [
        chain for chain in chains
        if chain.get("source_type") == source_type
    ]


def get_chain_summary(chains: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Get a summary of chain types and their counts.
    """
    summary = {}
    for chain in chains:
        chain_type = chain.get("chain_type", "Unknown")
        summary[chain_type] = summary.get(chain_type, 0) + 1
    return summary


# ==========================================
# LEGACY SUPPORT
# ==========================================

def trace_exfiltration_legacy(data_flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return trace_exfiltration(data_flows)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "trace_exfiltration",
    "trace_exfiltration_legacy",
    "filter_by_confidence",
    "filter_by_source_type",
    "get_chain_summary",
    "CHAIN_RULES",
]