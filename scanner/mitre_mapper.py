import json
from pathlib import Path


BASE_DIR = Path(__file__).parent

MITRE_FILE = (
    BASE_DIR
    / "data"
    / "mitre_attack_map.json"
)


def load_mitre_map():

    with open(
        MITRE_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


MITRE_ATTACK_MAP = load_mitre_map()


def map_to_mitre(finding):

    attack_type = finding.get(
        "attack_type"
    )

    finding["mitre"] = (
        MITRE_ATTACK_MAP.get(
            attack_type,
            []
        )
    )

    return finding


def enrich_findings(findings):

    return [
        map_to_mitre(f)
        for f in findings
    ]