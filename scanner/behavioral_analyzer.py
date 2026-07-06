"""
behavioral_analyzer.py
----------------------
Merges behavioral_extractor (feature vector filling)
with source_sink_tracker (alias-aware data flow).
Returns feature_vector + data_flows for downstream modules.
"""
import ast
from scanner.feature_vector      import create_feature_vector
from scanner.source_sink_tracker import analyze_data_flow, get_call_name

NETWORK_CALLS   = {"requests.get","requests.post","requests.put",
                   "requests.delete","socket.connect","socket.send","socket.sendall"}
PROCESS_CALLS   = {"subprocess.run","subprocess.Popen","subprocess.call",
                   "subprocess.check_output","os.system","os.popen"}
RECON_CALLS     = {"socket.gethostname","os.getlogin","platform.node",
                   "platform.system","platform.machine","os.getenv","os.environ.get"}
OBFUSCATION     = {"base64.b64encode","base64.b64decode","base64.encodebytes",
                   "zlib.compress","zlib.decompress","binascii.hexlify"}
ANTI_FORENSICS  = {"os.remove","os.unlink","shutil.rmtree","os.rename"}
PERSISTENCE     = {"winreg.SetValueEx","winreg.OpenKey"}
EVAL_EXEC       = {"eval","exec","compile"}

FORENSIC_KEYWORDS = {
    "history","bash_history",".bash_history","syslog","auth.log",
    "eventlog","wtmp","btmp","lastlog","audit","prefetch",
}

SUSPICIOUS_ENV = {"AWS_SECRET","AWS_ACCESS","TOKEN","PASSWORD","SECRET","API_KEY"}


def _contains_forensic_target(node):
    try:
        text = ast.unparse(node).lower()
        return any(k in text for k in FORENSIC_KEYWORDS)
    except Exception:
        return False


def analyze_behavior(tree: ast.AST, source: str) -> dict:
    """
    Returns:
        feature_vector  - dict of boolean behavioral flags
        data_flows      - list of source->transform->sink flow dicts
        tainted_vars    - variable names carrying sensitive data
    """
    fv = create_feature_vector()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        cname = get_call_name(node.func)

        # File access
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
                if "r" in mode:             fv["file_read"]   = True
                if any(c in mode for c in ("w","a","+")):
                                            fv["file_write"]  = True
            else:
                fv["file_read"] = True  # default mode is read

        if cname in NETWORK_CALLS:          fv["network_request"]    = True
        if cname in PROCESS_CALLS:          fv["subprocess"]         = True
        if cname in RECON_CALLS:            fv["system_recon"]       = True
        if cname in OBFUSCATION:            fv["obfuscation"]        = True
        if cname in EVAL_EXEC:              fv["eval_usage"]         = True
        if cname in PERSISTENCE:            fv["persistence_attempt"]= True

        # Anti-forensics
        if cname in ANTI_FORENSICS:
            fv["anti_forensics"] = True
            if node.args and _contains_forensic_target(node.args[0]):
                fv["data_flow_paths"].append("forensic_artifact_cleanup")

        # Credential env vars
        if cname in ("os.getenv", "os.environ.get") and node.args:
            if isinstance(node.args[0], ast.Constant):
                if any(k in node.args[0].value.upper() for k in SUSPICIOUS_ENV):
                    fv["credential_access"] = True

    # Data flow tracking via SourceSinkTracker
    flows = analyze_data_flow(tree)

    # Propagate flow findings back into feature vector
    for flow in flows:
        if "file" in flow["source"]:        fv["file_read"]       = True
        if "network" in flow["sink"]:       fv["network_request"] = True
        if flow["transforms"]:              fv["obfuscation"]     = True

    return {
        "feature_vector": fv,
        "data_flows":     flows,
        "tainted_vars":   [],
    }
