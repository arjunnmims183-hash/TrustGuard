"""
correlation_engine.py
---------------------
Converts raw data-flow findings into
security detections.
"""


def classify_flow(flow):

    source = flow["source"]

    sink = flow["sink"]

    transforms = flow.get(
        "transforms",
        []
    )

    # ==========================
    # Credential Theft
    # ==========================

    if source in {

        "env_var",
        "credential"

    }:

        return {

            "attack_type":
                "CREDENTIAL_THEFT",

            "severity":
                "CRITICAL",

            "confidence":
                95,

            "evidence":
                flow,
        }

    # ==========================
    # Obfuscated Exfiltration
    # ==========================

    if (
        source == "file_read"
        and len(transforms) > 0
    ):

        return {

            "attack_type":
                "OBFUSCATED_DATA_EXFILTRATION",

            "severity":
                "HIGH",

            "confidence":
                90,

            "evidence":
                flow,
        }

    # ==========================
    # Plain Exfiltration
    # ==========================

    if source == "file_read":

        return {

            "attack_type":
                "DATA_EXFILTRATION",

            "severity":
                "MEDIUM",

            "confidence":
                70,

            "evidence":
                flow,
        }

    # ==========================
    # User Input Theft
    # ==========================

    if source == "user_input":

        return {

            "attack_type":
                "INPUT_COLLECTION",

            "severity":
                "MEDIUM",

            "confidence":
                75,

            "evidence":
                flow,
        }

    return None


def analyze_flows(flows):

    findings = []

    for flow in flows:

        finding = classify_flow(
            flow
        )

        if finding:

            findings.append(
                finding
            )

    return findings


def correlate_behaviors(
    flows,
    behaviors
):

    findings = []

    # =====================================
    # BASIC FLOW DETECTIONS
    # =====================================

    for flow in flows:

        finding = classify_flow(flow)

        if finding:

            findings.append(
                finding
            )

    # =====================================
    # FLOW-BASED DETECTIONS
    # =====================================

    for flow in flows:

        # ---------------------------------
        # Stealthy Data Exfiltration
        # ---------------------------------

        if (
            flow["source"] == "file_read"
            and len(flow["transforms"]) > 0
            and behaviors["anti_forensics"]
        ):

            findings.append({

                "attack_type":
                    "STEALTHY_DATA_EXFILTRATION",

                "severity":
                    "CRITICAL",

                "confidence":
                    98,

                "evidence": {

                    "flow":
                        flow,

                    "behaviors": {

                        "anti_forensics":
                            True
                    }
                }
            })

        # ---------------------------------
        # Obfuscated Credential Exfiltration
        # ---------------------------------

        if (

            flow["source"] in {

                "env_var",
                "credential"

            }

            and

            len(
                flow["transforms"]
            ) > 0

            and

            flow["sink"].startswith(
                "requests"
            )

        ):

            findings.append({

                "attack_type":
                    "OBFUSCATED_CREDENTIAL_EXFILTRATION",

                "severity":
                    "CRITICAL",

                "confidence":
                    99,

                "evidence":
                    flow
            })

    # =====================================
    # BEHAVIOR-ONLY DETECTIONS
    # =====================================

    if (

        behaviors["credential_access"]

        and

        behaviors["network_request"]

        and

        behaviors["obfuscation"]

    ):

        findings.append({

            "attack_type":
                "ADVANCED_CREDENTIAL_THEFT",

            "severity":
                "CRITICAL",

            "confidence":
                97,

            "evidence": {

                "credential_access":
                    True,

                "network_request":
                    True,

                "obfuscation":
                    True
            }
        })

    return findings


# =====================================
# PRIORITY ENGINE
# =====================================

def prioritize_findings(findings):

    attack_types = {

        finding["attack_type"]
        for finding in findings
    }

    # ----------------------------------
    # Stealthy Exfiltration wins
    # ----------------------------------

    if "STEALTHY_DATA_EXFILTRATION" in attack_types:

        findings = [

            f for f in findings

            if f["attack_type"] not in {

                "DATA_EXFILTRATION",
                "OBFUSCATED_DATA_EXFILTRATION"
            }
        ]

    # ----------------------------------
    # Obfuscated Credential Exfiltration wins
    # ----------------------------------

    if "OBFUSCATED_CREDENTIAL_EXFILTRATION" in attack_types:

        findings = [

            f for f in findings

            if f["attack_type"] not in {

                "CREDENTIAL_THEFT",
                "ADVANCED_CREDENTIAL_THEFT"
            }
        ]

    return findings