from scanner.parser import parse_file
from scanner.source_sink_tracker import analyze_data_flow
from scanner.behavioral_extractor import extract_behavior
from scanner.correlation_engine import (
    analyze_flows,
    correlate_behaviors,
    prioritize_findings 
)



import sys


def main():

    target = sys.argv[1]

    result = parse_file(target)

    if result["error"]:
        print(result["error"])
        return

    tree = result["ast_tree"]

    flows = analyze_data_flow(tree)

    behaviors = extract_behavior(
        tree,
        result["source"]
    )

    findings = []

    findings.extend(
        analyze_flows(flows)
    )

    findings.extend(
        correlate_behaviors(
            flows,
            behaviors
        )
    )

    findings = prioritize_findings(
        findings
    )

    print("\n===== FLOWS =====\n")

    for flow in flows:
        print(flow)

    print("\n===== FINDINGS =====\n")

    for finding in findings:
        print(finding)


if __name__ == "__main__":
    main()  