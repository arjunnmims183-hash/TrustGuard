"""
threat_explainer.py
-------------------
Converts source -> transform -> sink flows
into analyst-readable explanations.
"""


SOURCE_DESCRIPTIONS = {

    "file_read":
        "Reads data from a local file.",

    "env_var":
        "Reads information from environment variables.",

    "credential":
        "Collects credentials from the user.",

    "user_input":
        "Collects user supplied input.",

    "network_recv":
        "Receives data from a remote source."
}


TRANSFORM_DESCRIPTIONS = {

    "encode":
        "Converts text into bytes.",

    "base64_encode":
        "Encodes data using Base64.",

    "zlib_compress":
        "Compresses data using ZLIB.",

    "gzip_compress":
        "Compresses data using GZIP.",

    "hexlify":
        "Converts binary data into hexadecimal.",

    "json_serialize":
        "Serializes data into JSON.",

    "serialize":
        "Serializes Python objects."
}


SINK_DESCRIPTIONS = {

    "requests.post":
        "Transmits data through an HTTP POST request.",

    "requests.put":
        "Uploads data using HTTP PUT.",

    "requests.patch":
        "Uploads data using HTTP PATCH.",

    "requests.request":
        "Sends data through a generic HTTP request.",

    "socket.send":
        "Sends data through a network socket.",

    "socket.sendall":
        "Sends all data through a network socket.",

    "urllib.request.urlopen":
        "Sends data through a URL request.",

    "websocket.send":
        "Sends data through a WebSocket.",

    "ftplib.FTP.storbinary":
        "Uploads data to an FTP server.",

    "smtplib.SMTP.sendmail":
        "Transmits data via email.",

    "paramiko.SSHClient.exec_command":
        "Executes a remote SSH command."
}


def explain_flow(flow):

    source = flow.get(
        "source",
        "unknown"
    )

    sink = flow.get(
        "sink",
        "unknown"
    )

    transforms = flow.get(
        "transforms",
        []
    )

    details = []

    # ==========================
    # Source
    # ==========================

    details.append(

        SOURCE_DESCRIPTIONS.get(
            source,
            f"Source detected: {source}"
        )
    )

    # ==========================
    # Transforms
    # ==========================

    for transform in transforms:

        details.append(

            TRANSFORM_DESCRIPTIONS.get(
                transform,
                f"Transformation detected: {transform}"
            )
        )

    # ==========================
    # Sink
    # ==========================

    details.append(

        SINK_DESCRIPTIONS.get(
            sink,
            f"Sink detected: {sink}"
        )
    )

    # ==========================
    # Summary
    # ==========================

    summary = (

        f"Data originating from "

        f"'{source}' "

        f"was transformed "

        f"{len(transforms)} "

        f"time(s) before "

        f"reaching "

        f"'{sink}'."
    )

    # ==========================
    # Threat Interpretation
    # ==========================

    if source == "file_read":

        if len(transforms) > 0:

            summary += (

                " This resembles an "
                "obfuscated data "
                "exfiltration pattern."
            )

        else:

            summary += (

                " This resembles a "
                "direct data "
                "exfiltration pattern."
            )

    elif source in {

        "env_var",
        "credential"

    }:

        if len(transforms) > 0:

            summary += (

                " This resembles "
                "credential theft "
                "with obfuscation."
            )

        else:

            summary += (

                " This resembles "
                "credential theft."
            )

    elif source == "user_input":

        summary += (

            " This resembles "
            "user input collection "
            "and transmission."
        )

    elif source == "network_recv":

        summary += (

            " Data received from "
            "a remote source is "
            "being retransmitted."
        )

    # ==========================
    # Return Report
    # ==========================

    return {

        "summary":
            summary,

        "details":
            details,

        "source":
            source,

        "sink":
            sink,

        "transform_count":
            len(transforms)
    }