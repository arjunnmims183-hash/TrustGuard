"""
attack_graph.py
---------------
Builds attack graphs from data flows for visualization and analysis.

The attack graph shows the flow of data from sources through transforms
to sinks, making it easy to visualize attack chains.

Example:
    file_read → base64_encode → zlib_compress → requests.post
"""

from typing import List, Dict, Any, Optional, Union, Set, Tuple


# ==========================================
# ATTACK GRAPH CLASS
# ==========================================

class AttackGraph:
    """
    Simple directed graph for attack visualization.
    
    Attributes:
        nodes: Set of node names in the graph
        edges: List of (source, target) tuples
    """
    
    def __init__(self):
        self.nodes: Set[str] = set()
        self.edges: List[Tuple[str, str]] = []

    def add_edge(self, src: str, dst: str) -> None:
        """
        Add a directed edge between two nodes.
        
        Args:
            src: Source node name
            dst: Destination node name
        """
        self.nodes.add(src)
        self.nodes.add(dst)
        self.edges.append((src, dst))

    def add_flow(self, flow: Dict[str, Any]) -> None:
        """
        Add a complete flow to the graph.
        
        Args:
            flow: Flow dictionary with source, transforms, sink
        """
        if "source" not in flow:
            return
        
        source = flow.get("source", "unknown")
        sink = flow.get("sink", "unknown")
        transforms = flow.get("transforms", [])
        
        previous = source
        for transform in transforms:
            self.add_edge(previous, transform)
            previous = transform
        
        self.add_edge(previous, sink)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert graph to dictionary representation.
        
        Returns:
            Dictionary with nodes, edges, and counts
        """
        return {
            "nodes": list(self.nodes),
            "edges": [{"source": src, "target": dst} for src, dst in self.edges],
            "edge_count": len(self.edges),
            "node_count": len(self.nodes),
        }

    def is_empty(self) -> bool:
        """Check if the graph has no edges."""
        return len(self.edges) == 0

    def get_nodes_by_type(self) -> Dict[str, List[str]]:
        """
        Group nodes by type (source, transform, sink).
        
        Returns:
            Dictionary with node types as keys and lists of nodes
        """
        sources = []
        transforms = []
        sinks = []
        
        # Track nodes that appear as sources (first in edge) and sinks (last in edge)
        source_nodes = {edge[0] for edge in self.edges}
        sink_nodes = {edge[1] for edge in self.edges}
        
        for node in self.nodes:
            if node in source_nodes and node not in sink_nodes:
                sources.append(node)
            elif node in sink_nodes and node not in source_nodes:
                sinks.append(node)
            else:
                transforms.append(node)
        
        return {
            "sources": sources,
            "transforms": transforms,
            "sinks": sinks,
        }


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _extract_flows_from_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract data flows from correlation findings.
    """
    flows = []
    for finding in findings:
        evidence = finding.get("evidence", {})
        if "flow" in evidence:
            flows.append(evidence["flow"])
        elif "data_flows" in evidence:
            flows.extend(evidence["data_flows"])
        elif "source" in evidence and "sink" in evidence:
            flows.append(evidence)
    return flows


def _is_flow(item: Dict[str, Any]) -> bool:
    """
    Check if a dictionary is a flow (has source and sink).
    """
    return "source" in item or "sink" in item


def _is_finding(item: Dict[str, Any]) -> bool:
    """
    Check if a dictionary is a finding (has attack_type).
    """
    return "attack_type" in item


# ==========================================
# MAIN BUILD FUNCTION
# ==========================================

def build_attack_graph(
    flows_or_findings: Union[List[Dict[str, Any]], Dict[str, Any]],
    data_flows: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Build an attack graph from data flows or correlation findings.
    
    Args:
        flows_or_findings: List of data flows OR correlation findings
        data_flows: Optional data flows if first arg is findings
        
    Returns:
        Dictionary representation of the attack graph
    """
    graph = AttackGraph()
    flows_to_process = []
    
    # =====================================
    # Case 1: Dict input (single finding)
    # =====================================
    if isinstance(flows_or_findings, dict):
        evidence = flows_or_findings.get("evidence", {})
        if "flow" in evidence:
            flows_to_process = [evidence["flow"]]
        elif "data_flows" in evidence:
            flows_to_process = evidence["data_flows"]
        elif "source" in evidence and "sink" in evidence:
            flows_to_process = [evidence]
    
    # =====================================
    # Case 2: List input
    # =====================================
    elif isinstance(flows_or_findings, list):
        if not flows_or_findings:
            pass
        elif _is_flow(flows_or_findings[0]):
            # It's a list of flows
            flows_to_process = flows_or_findings
        else:
            # It's a list of findings, extract flows
            flows_to_process = _extract_flows_from_findings(flows_or_findings)
    
    # =====================================
    # Case 3: Additional data_flows
    # =====================================
    if data_flows and isinstance(data_flows, list):
        flows_to_process.extend(data_flows)
    
    # =====================================
    # Build the graph
    # =====================================
    for flow in flows_to_process:
        if isinstance(flow, dict) and "source" in flow:
            graph.add_flow(flow)
    
    return graph.to_dict()


# ==========================================
# OUTPUT FUNCTIONS
# ==========================================

def print_graph(graph: Union[AttackGraph, Dict[str, Any]]) -> None:
    """
    Print the attack graph in a readable format.
    
    Args:
        graph: AttackGraph object or dictionary
    """
    print("\n===== ATTACK GRAPH =====\n")
    
    # If it's a dict, extract edges
    if isinstance(graph, dict):
        edges = graph.get("edges", [])
        if not edges:
            print("  (empty graph)")
            return
        
        for edge in edges:
            print(f"  {edge.get('source', '?')} --> {edge.get('target', '?')}")
        
        print(f"\n  Nodes: {graph.get('node_count', 0)}")
        print(f"  Edges: {graph.get('edge_count', 0)}")
        return
    
    # If it's an AttackGraph object
    if hasattr(graph, 'edges'):
        if not graph.edges:
            print("  (empty graph)")
            return
        
        for src, dst in graph.edges:
            print(f"  {src} --> {dst}")
        
        print(f"\n  Nodes: {len(graph.nodes)}")
        print(f"  Edges: {len(graph.edges)}")
    else:
        print("  (no graph data)")


def graph_to_mermaid(graph: Dict[str, Any]) -> str:
    """
    Convert graph to Mermaid flowchart format.
    
    Args:
        graph: Graph dictionary from build_attack_graph
        
    Returns:
        Mermaid flowchart string
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    
    if not nodes or not edges:
        return "graph TD\n    NoData[No attack graph data]"
    
    lines = ["graph TD"]
    
    # Add nodes with styling
    for node in nodes:
        safe_name = _sanitize_name(node)
        lines.append(f"    {safe_name}[{node}]")
    
    # Add edges
    for edge in edges:
        src = _sanitize_name(edge.get("source", ""))
        dst = _sanitize_name(edge.get("target", ""))
        lines.append(f"    {src} --> {dst}")
    
    return "\n".join(lines)


def graph_to_dot(graph: Dict[str, Any]) -> str:
    """
    Convert graph to DOT format (for GraphViz).
    
    Args:
        graph: Graph dictionary from build_attack_graph
        
    Returns:
        DOT format string
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    
    if not nodes or not edges:
        return 'digraph G {\n    "No Data";\n}'
    
    lines = ['digraph G {']
    lines.append('    rankdir=LR;')
    
    # Add nodes
    for node in nodes:
        safe_name = _sanitize_name(node)
        lines.append(f'    "{safe_name}" [label="{node}"];')
    
    # Add edges
    for edge in edges:
        src = _sanitize_name(edge.get("source", ""))
        dst = _sanitize_name(edge.get("target", ""))
        lines.append(f'    "{src}" -> "{dst}";')
    
    lines.append('}')
    return "\n".join(lines)


def _sanitize_name(name: str) -> str:
    """
    Sanitize a name for use in graph formats.
    Removes special characters that cause issues in DOT/Mermaid.
    """
    # Replace problematic characters
    replacements = {
        ".": "_",
        "-": "_",
        " ": "_",
        "(": "",
        ")": "",
        "[": "",
        "]": "",
        "{": "",
        "}": "",
    }
    result = name
    for old, new in replacements.items():
        result = result.replace(old, new)
    return result


def get_graph_statistics(graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get statistics about the attack graph.
    
    Args:
        graph: Graph dictionary from build_attack_graph
        
    Returns:
        Dictionary with graph statistics
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    
    # Count node types
    source_count = 0
    sink_count = 0
    transform_count = 0
    
    # Find nodes that appear as sources (first in edge)
    source_nodes = {edge.get("source", "") for edge in edges}
    sink_nodes = {edge.get("target", "") for edge in edges}
    
    for node in nodes:
        if node in source_nodes and node not in sink_nodes:
            source_count += 1
        elif node in sink_nodes and node not in source_nodes:
            sink_count += 1
        else:
            transform_count += 1
    
    return {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "source_count": source_count,
        "sink_count": sink_count,
        "transform_count": transform_count,
        "has_cycles": False,  # Could implement cycle detection
        "max_path_length": _get_max_path_length(edges),
    }


def _get_max_path_length(edges: List[Dict[str, str]]) -> int:
    """
    Estimate the maximum path length in the graph.
    """
    if not edges:
        return 0
    
    # Build adjacency list
    adj = {}
    for edge in edges:
        src = edge.get("source", "")
        dst = edge.get("target", "")
        if src not in adj:
            adj[src] = []
        adj[src].append(dst)
    
    # DFS to find longest path
    visited = set()
    max_length = 0
    
    def dfs(node: str, depth: int) -> int:
        nonlocal max_length
        if node in visited:
            return depth
        visited.add(node)
        max_length = max(max_length, depth)
        for neighbor in adj.get(node, []):
            dfs(neighbor, depth + 1)
        visited.remove(node)
        return max_length
    
    for node in adj:
        dfs(node, 1)
    
    return max_length


# ==========================================
# LEGACY SUPPORT
# ==========================================

def build_attack_graph_legacy(
    flows_or_findings: Union[List[Dict[str, Any]], Dict[str, Any]],
    data_flows: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Legacy wrapper for backward compatibility.
    """
    return build_attack_graph(flows_or_findings, data_flows)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "AttackGraph",
    "build_attack_graph",
    "build_attack_graph_legacy",
    "print_graph",
    "graph_to_mermaid",
    "graph_to_dot",
    "get_graph_statistics",
]