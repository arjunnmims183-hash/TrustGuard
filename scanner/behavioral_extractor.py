import ast

from scanner.feature_vector import create_feature_vector


NETWORK_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "socket.connect",
    "socket.send",
}


NETWORK_RECEIVE_CALLS = {
    "requests.get",
    "socket.recv",
}


PROCESS_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "os.system",
    "os.popen",
}


RECON_CALLS = {
    "socket.gethostname",
    "os.getenv",
    "platform.system",
    "platform.machine",
    "platform.node",
}


ANTI_FORENSICS_CALLS = {
    "os.remove",
    "os.unlink",
    "shutil.rmtree",
    "os.rename",
    "os.replace",
}


FORENSIC_TARGET_KEYWORDS = {
    "history",
    "bash_history",
    ".bash_history",
    "eventlog",
    "event_log",
    "logs",
    "log",
    "journal",
    "syslog",
    "audit",
    "audit.log",
    "security.evtx",
    "system.evtx",
    "application.evtx",
    "prefetch",
    "recent",
    "recycle",
    "temp",
    "tmp",
}


SUSPICIOUS_ENV = {
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "TOKEN",
    "PASSWORD",
    "SECRET",
}


OBFUSCATION_CALLS = {
    "base64.b64encode",
    "base64.b64decode",

    "zlib.compress",
    "gzip.compress",

    "binascii.hexlify",

    "pickle.dumps",

    "json.dumps",
}


def get_call_name(node):

    if isinstance(node, ast.Name):
        return node.id

    elif isinstance(node, ast.Attribute):

        parent = get_call_name(node.value)

        if parent:
            return f"{parent}.{node.attr}"

        return node.attr

    return None


def contains_forensic_target(node):

    try:

        target_text = ast.unparse(node).lower()

        return any(
            keyword in target_text
            for keyword in FORENSIC_TARGET_KEYWORDS
        )

    except Exception:

        return False


def extract_behavior(tree, source):

    features = create_feature_vector()

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        call_name = get_call_name(node.func)

        # =====================================
        # FILE ACTIVITY
        # =====================================

        if isinstance(node.func, ast.Name):

            if node.func.id == "open":

                # open("file")
                if len(node.args) < 2:

                    features["file_read"] = True

                # open("file", "mode")
                elif isinstance(
                    node.args[1],
                    ast.Constant
                ):

                    mode = str(
                        node.args[1].value
                    )

                    if "r" in mode:

                        features["file_read"] = True

                    if (
                        "w" in mode
                        or "a" in mode
                        or "+" in mode
                    ):

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
        # ANTI FORENSICS
        # =====================================

        if call_name in ANTI_FORENSICS_CALLS:

            features["anti_forensics"] = True

            if node.args:

                if contains_forensic_target(
                    node.args[0]
                ):

                    features[
                        "data_flow_paths"
                    ].append(
                        "forensic_artifact_cleanup"
                    )

        # =====================================
        # CREDENTIAL ACCESS
        # =====================================

        if call_name == "os.getenv":

            if node.args:

                if isinstance(
                    node.args[0],
                    ast.Constant
                ):

                    env_name = str(
                        node.args[0].value
                    )

                    for keyword in SUSPICIOUS_ENV:

                        if keyword in env_name.upper():

                            features[
                                "credential_access"
                            ] = True

        # =====================================
        # OBFUSCATION
        # =====================================

        if call_name in OBFUSCATION_CALLS:

            features["obfuscation"] = True

    return features