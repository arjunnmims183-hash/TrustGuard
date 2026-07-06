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
    for flow in flows:

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
    return findings