import sys

from scanner.parser import parse_file

from scanner.source_sink_tracker import (
    analyze_data_flow
)

from scanner.behavioral_extractor import (
    extract_behavior
)

from scanner.correlation_engine import (
    correlate_behaviors
)

from scanner.mitre_mapper import (
    enrich_findings
)


def main():

    if len(sys.argv) != 2:

        print(
            "Usage: python test_phase3d.py <sample.py>"
        )

        return

    filepath = sys.argv[1]

    result = parse_file(filepath)

    if result["error"]:

        print(result["error"])

        return

    tree = result["ast_tree"]

    flows = analyze_data_flow(tree)

    behaviors = extract_behavior(
        tree,
        result["source"]
    )

    findings = correlate_behaviors(
    flows,
    behaviors
    )

    print("\nFLOWS:")
    print(flows)

    print("\nBEHAVIORS:")
    print(behaviors)

    print("\nRAW FINDINGS:")
    print(findings)

    findings = enrich_findings(
        findings
    )

    print("\n===== FINDINGS =====\n")

    for finding in findings:

        print(
            "ATTACK TYPE:",
            finding["attack_type"]
        )

        print(
            "SEVERITY:",
            finding["severity"]
        )

        print(
            "CONFIDENCE:",
            finding["confidence"]
        )

        print("\nMITRE TECHNIQUES:")

        for technique in finding.get(
            "mitre",
            []
        ):

            print(
                f"{technique['id']} - "
                f"{technique['name']}"
            )

        print("\n" + "-" * 50)


if __name__ == "__main__":
    main()