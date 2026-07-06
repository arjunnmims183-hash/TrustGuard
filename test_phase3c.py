from scanner.parser import parse_file

from scanner.source_sink_tracker import (
    analyze_data_flow
)

from scanner.threat_explainer import (
    explain_flow
)

import sys


def main():

    if len(sys.argv) < 2:

        print(
            "Usage: python test_phase3c.py <sample_file>"
        )

        return

    target = sys.argv[1]

    result = parse_file(target)

    if result["error"]:

        print(result["error"])
        return

    tree = result["ast_tree"]

    flows = analyze_data_flow(tree)

    if not flows:

        print("No flows detected.")
        return

    for flow in flows:

        report = explain_flow(flow)

        print("\n===== FLOW =====\n")
        print(flow)

        print("\n===== SUMMARY =====\n")
        print(report["summary"])

        print("\n===== DETAILS =====\n")

        for item in report["details"]:
            print("-", item)


if __name__ == "__main__":
    main()  