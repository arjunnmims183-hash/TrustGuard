"""
source_sink_tracker.py
----------------------
Tracks variable data flow: source -> transforms -> sink.
Handles alias chains (a = b = c = data) and multi-hop transforms.

Data flows track:
    1. Source detection - where data originates (file read, env var, user input, etc.)
    2. Transform tracking - how data is modified (encode, compress, serialize, etc.)
    3. Sink detection - where data ends up (network, file write, etc.)
    4. Alias resolution - tracking variable assignments and renames
"""

import ast
from typing import Dict, List, Any, Optional, Set, Tuple

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.source_sink_mappings import (
    NETWORK_SINKS,
    TRANSFORM_FUNCTIONS,
    detect_source,
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def get_call_name(node: ast.AST) -> Optional[str]:
    """
    Reconstruct a dotted call name from the AST node.
    
    Examples:
        - requests.post -> "requests.post"
        - os.getenv -> "os.getenv"
        - eval -> "eval"
    """
    if isinstance(node, ast.Name):
        return node.id
    
    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    
    return None


# ==========================================
# SOURCE SINK TRACKER CLASS
# ==========================================

class SourceSinkTracker:
    """
    Tracks data flow from sources to sinks through variable assignments.
    
    Attributes:
        variable_sources: Dict[str, str] - variable -> source type
        variable_transforms: Dict[str, Dict] - variable -> transform info
        variable_aliases: Dict[str, str] - alias -> original variable
        variable_versions: Dict[str, int] - variable -> version number
        file_handles: Dict[str, str] - file handle -> source type
        flows: List[Dict] - detected data flows
    """

    def __init__(self):
        self.variable_sources: Dict[str, str] = {}
        self.variable_transforms: Dict[str, Dict[str, Any]] = {}
        self.variable_aliases: Dict[str, str] = {}
        self.variable_versions: Dict[str, int] = {}
        self.file_handles: Dict[str, str] = {}
        self.flows: List[Dict[str, Any]] = []

    # =====================================
    # VERSION MANAGEMENT
    # =====================================

    def create_new_version(self, var: str) -> str:
        """
        Create a new versioned variable name.
        
        Example: token#1, token#2, etc.
        """
        version = self.variable_versions.get(var, 0) + 1
        self.variable_versions[var] = version
        return f"{var}#{version}"

    def current_version(self, var: str) -> str:
        """
        Get the current version of a variable.
        
        Returns:
            str: Versioned variable name (e.g., token#1)
        """
        version = self.variable_versions.get(var)
        if version is None:
            return var
        return f"{var}#{version}"

    # =====================================
    # PASS 1 - TRACK VARIABLES
    # =====================================

    def track(self, tree: ast.AST) -> None:
        """
        First pass: track all variable assignments and sources.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.With):
                self._handle_with(node)
                for stmt in node.body:
                    if isinstance(stmt, ast.Assign):
                        self._handle_assignment(stmt)
            elif isinstance(node, ast.Assign):
                self._handle_assignment(node)

    # =====================================
    # WITH OPEN(...)
    # =====================================

    def _handle_with(self, node: ast.With) -> None:
        """
        Handle 'with open(...) as f' patterns.
        """
        for item in node.items:
            if not isinstance(item.context_expr, ast.Call):
                continue
            
            if get_call_name(item.context_expr.func) != "open":
                continue
            
            if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                self.file_handles[item.optional_vars.id] = "file_read"

    # =====================================
    # ASSIGNMENTS
    # =====================================

    def _handle_assignment(self, node: ast.Assign) -> None:
        """
        Handle variable assignments and track sources/transforms.
        """
        if not node.targets:
            return
        
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            return
        
        var = target.id
        value = node.value

        # =====================================
        # Case 1: Alias propagation (x = y)
        # =====================================
        if isinstance(value, ast.Name):
            left = self.create_new_version(var)
            right = self.current_version(value.id)
            self.variable_aliases[left] = right
            return

        # =====================================
        # Case 2: Function calls
        # =====================================
        if not isinstance(value, ast.Call):
            return
        
        func = value.func
        call_name = get_call_name(func)

        # Normalize variable.encode() calls
        if isinstance(func, ast.Attribute) and func.attr == "encode":
            call_name = "str.encode"

        # =====================================
        # File handle read (f.read())
        # =====================================
        if (isinstance(func, ast.Attribute) and 
            func.attr == "read" and 
            isinstance(func.value, ast.Name) and 
            func.value.id in self.file_handles):
            
            versioned_var = self.create_new_version(var)
            self.variable_sources[versioned_var] = "file_read"
            return

        # =====================================
        # Direct Sources
        # =====================================
        source = detect_source(call_name)
        if source:
            versioned_var = self.create_new_version(var)
            self.variable_sources[versioned_var] = source
            return

        # =====================================
        # Transforms
        # =====================================
        if call_name in TRANSFORM_FUNCTIONS:
            self._handle_transform(node, var, func, call_name)

    def _handle_transform(self, node: ast.Assign, var: str, func: ast.AST, call_name: str) -> None:
        """
        Handle transform operations (encode, base64, compress, etc.)
        """
        # =====================================
        # Case: str.encode()
        # =====================================
        if call_name == "str.encode":
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                input_var = self.current_version(func.value.id)
                new_var = self.create_new_version(var)
                
                # Self-reassignment case: b = b.encode()
                if func.value.id == var:
                    previous_version = self.variable_versions.get(var, 1) - 1
                    if previous_version > 0:
                        input_var = f"{var}#{previous_version}"
                
                self.variable_transforms[new_var] = {
                    "transform": "encode",
                    "input": input_var
                }
            return

        # =====================================
        # Case: Normal transforms
        # =====================================
        if not node.value.args:
            return
        
        arg = node.value.args[0]

        # =====================================
        # Case 1: base64.b64encode(data)
        # =====================================
        if isinstance(arg, ast.Name):
            input_var = self.current_version(arg.id)
            new_var = self.create_new_version(var)
            
            # Self-reassignment case: data = base64.b64encode(data)
            if arg.id == var:
                previous_version = self.variable_versions.get(var, 1) - 1
                if previous_version > 0:
                    input_var = f"{var}#{previous_version}"
            
            self.variable_transforms[new_var] = {
                "transform": TRANSFORM_FUNCTIONS[call_name],
                "input": input_var
            }

        # =====================================
        # Case 2: base64.b64encode(token.encode())
        # =====================================
        elif isinstance(arg, ast.Call):
            if (isinstance(arg.func, ast.Attribute) and 
                arg.func.attr == "encode" and 
                isinstance(arg.func.value, ast.Name)):
                
                original_var = arg.func.value.id
                temp_var = f"{var}_inner"
                
                self.variable_transforms[temp_var] = {
                    "transform": "encode",
                    "input": self.current_version(original_var)
                }
                
                new_var = self.create_new_version(var)
                self.variable_transforms[new_var] = {
                    "transform": TRANSFORM_FUNCTIONS[call_name],
                    "input": temp_var
                }

    # =====================================
    # ALIAS RESOLUTION
    # =====================================

    def _resolve_alias(self, var: str) -> str:
        """
        Resolve variable aliases to their original version.
        
        Example: a#1 -> b#1 -> token#1
        """
        visited = set()
        while var in self.variable_aliases and var not in visited:
            visited.add(var)
            var = self.variable_aliases[var]
        return var

    # =====================================
    # TRANSFORM CHAIN RESOLUTION
    # =====================================

    def _resolve_transform_chain(self, var: str) -> Tuple[str, List[str]]:
        """
        Resolve the full transform chain for a variable.
        
        Returns:
            Tuple of (source_var, list_of_transforms)
        """
        transforms = []
        visited = set()
        current = var

        while current in self.variable_transforms and current not in visited:
            visited.add(current)
            info = self.variable_transforms[current]
            transforms.append(info["transform"])
            current = self._resolve_alias(info["input"])

        return current, list(reversed(transforms))

    # =====================================
    # PASS 2 - DETECT SINKS
    # =====================================

    def detect_sinks(self, tree: ast.AST) -> None:
        """
        Second pass: detect sinks (network calls) and trace data flows.
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = get_call_name(node.func)
            if call_name not in NETWORK_SINKS:
                continue

            # Collect all arguments (positional + keyword)
            args = list(node.args) + [kw.value for kw in node.keywords]

            for arg in args:
                # Variable argument
                if isinstance(arg, ast.Name):
                    latest = self.current_version(arg.id)
                    self._resolve_flow(latest, call_name)

                # Dict literal argument (like data= {...})
                elif isinstance(arg, ast.Dict):
                    for value in arg.values:
                        if isinstance(value, ast.Name):
                            latest = self.current_version(value.id)
                            self._resolve_flow(latest, call_name)

    # =====================================
    # FLOW RESOLUTION
    # =====================================

    def _resolve_flow(self, var: str, sink: str) -> None:
        """
        Resolve a data flow from source to sink.
        """
        resolved = self._resolve_alias(var)

        # =====================================
        # Case 1: Source -> Sink (no transforms)
        # =====================================
        if resolved in self.variable_sources:
            self.flows.append({
                "source": self.variable_sources[resolved],
                "transforms": [],
                "sink": sink,
                "source_var": resolved,
                "sink_call": sink,
            })
            return

        # =====================================
        # Case 2: Source -> Transforms -> Sink
        # =====================================
        source_var, transforms = self._resolve_transform_chain(resolved)

        if source_var in self.variable_sources:
            self.flows.append({
                "source": self.variable_sources[source_var],
                "transforms": transforms,
                "sink": sink,
                "source_var": source_var,
                "sink_call": sink,
            })

    # =====================================
    # RESULTS
    # =====================================

    def get_flows(self) -> List[Dict[str, Any]]:
        """
        Return all detected data flows.
        """
        return self.flows


# ==========================================
# PUBLIC API
# ==========================================

def analyze_data_flow(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Analyze data flow through a Python AST.
    
    Args:
        tree (ast.AST): Parsed AST to analyze
        
    Returns:
        List of data flows with source, transforms, and sink information
    """
    tracker = SourceSinkTracker()
    tracker.track(tree)
    tracker.detect_sinks(tree)
    return tracker.get_flows()


# ==========================================
# LEGACY SUPPORT
# ==========================================

def analyze_data_flow_legacy(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return analyze_data_flow(tree)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "analyze_data_flow",
    "analyze_data_flow_legacy",
    "SourceSinkTracker",
    "get_call_name",
]