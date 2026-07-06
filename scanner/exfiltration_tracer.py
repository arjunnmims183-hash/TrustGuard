"""
exfiltration_tracer.py
----------------------
Classifies data flows from source_sink_tracker into named attack chains.
"""
from typing import List, Dict, Any

NETWORK_SINKS  = {"requests.post","requests.put","socket.send",
                  "socket.sendall","ftplib.FTP.storbinary","smtplib.SMTP.sendmail"}
FILE_SOURCES   = {"file_read"}
ENV_SOURCES    = {"env_var","credential"}
ALL_SOURCES    = {"file_read","env_var","credential","user_input","network_recv"}

CHAIN_RULES = [
    {
        "name":        "Data Exfiltration",
        "sources":     {"file_read"},
        "sinks":       NETWORK_SINKS,
        "confidence":  "HIGH",
        "description": "File data read and transmitted to a remote server.",
    },
    {
        "name":        "Credential Exfiltration",
        "sources":     {"env_var","credential"},
        "sinks":       NETWORK_SINKS,
        "confidence":  "CRITICAL",
        "description": "Credentials/env secrets harvested and sent over the network.",
    },
    {
        "name":        "Encoded Exfiltration",
        "sources":     ALL_SOURCES,
        "sinks":       NETWORK_SINKS,
        "requires_transform": True,
        "confidence":  "HIGH",
        "description": "Data encoded/transformed before transmission — hiding content from inspection.",
    },
    {
        "name":        "Remote Code Execution via Tainted Input",
        "sources":     {"user_input","network_recv"},
        "sinks":       {"eval","exec","compile","os.system","subprocess.run","subprocess.Popen"},
        "confidence":  "CRITICAL",
        "description": "User/network input flows into eval()/exec() — attacker-controlled code execution.",
    },
]


def trace_exfiltration(data_flows: List[Dict]) -> List[Dict[str, Any]]:
    chains = []
    for flow in data_flows:
        for rule in CHAIN_RULES:
            if flow["source"] not in rule["sources"]:
                continue
            if flow["sink"] not in rule["sinks"]:
                continue
            if rule.get("requires_transform") and not flow.get("transforms"):
                continue
            chains.append({
                "chain_type":  rule["name"],
                "confidence":  rule["confidence"],
                "description": rule["description"],
                "source_var":  flow.get("source_var", "?"),
                "source_type": flow["source"],
                "transforms":  flow.get("transforms", []),
                "sink_call":   flow["sink"],
                "has_encoding":len(flow.get("transforms", [])) > 0,
            })

    # Deduplicate by chain_type + source_var + sink
    seen, unique = set(), []
    for c in chains:
        key = (c["chain_type"], c["source_var"], c["sink_call"])
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique
