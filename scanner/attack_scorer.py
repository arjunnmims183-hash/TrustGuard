"""
attack_scorer.py
----------------
Assigns a complexity/threat score to an attack flow.

Example:

file_read
    |
base64_encode
    |
zlib_compress
    |
requests.post

=> Score: 95
=> Level: CRITICAL
"""

# ==========================================
# SOURCE WEIGHTS
# ==========================================

SOURCE_SCORES = {

    "file_read": 20,

    "env_var": 40,

    "credential": 50,

    "user_input": 15,

    "network_recv": 25,
}


# ==========================================
# TRANSFORM WEIGHTS
# ==========================================

TRANSFORM_SCORES = {

    "encode": 5,

    "base64_encode": 15,

    "zlib_compress": 20,

    "gzip_compress": 20,

    "hexlify": 15,

    "serialize": 25,

    "json_serialize": 10,
}


# ==========================================
# SINK WEIGHTS
# ==========================================

SINK_SCORES = {

    "requests.post": 20,

    "requests.put": 20,

    "requests.patch": 20,

    "socket.send": 25,

    "socket.sendall": 25,

    "smtplib.SMTP.sendmail": 30,

    "ftplib.FTP.storbinary": 25,
}


class AttackScorer:

    def __init__(self):
        pass

    # ======================================
    # THREAT LEVEL
    # ======================================

    def get_level(self, score):

        if score >= 90:
            return "CRITICAL"

        if score >= 70:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        return "LOW"

    # ======================================
    # FLOW SCORING
    # ======================================

    def score_flow(self, flow):

        score = 0

        # -----------------------------
        # Source Weight
        # -----------------------------

        score += SOURCE_SCORES.get(
            flow["source"],
            0
        )

        # -----------------------------
        # Transform Weight
        # -----------------------------

        transforms = flow.get(
            "transforms",
            []
        )

        for transform in transforms:

            score += TRANSFORM_SCORES.get(
                transform,
                10
            )

        # -----------------------------
        # Sink Weight
        # -----------------------------

        score += SINK_SCORES.get(
            flow["sink"],
            10
        )

        # -----------------------------
        # Complexity Bonus
        # -----------------------------

        if len(transforms) >= 2:

            score += 15

        if len(transforms) >= 4:

            score += 20

        # -----------------------------
        # Clamp Score
        # -----------------------------

        if score > 100:
            score = 100

        return {

            "score": score,

            "level": self.get_level(
                score
            ),

            "source": flow["source"],

            "sink": flow["sink"],

            "transforms": transforms
        }

    # ======================================
    # MULTIPLE FLOWS
    # ======================================

    def score_all(self, flows):

        results = []

        for flow in flows:

            results.append(
                self.score_flow(flow)
            )

        return results