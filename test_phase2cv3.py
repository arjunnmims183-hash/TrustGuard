from scanner.parser import parse_file

from scanner.source_sink_tracker import (
    analyze_data_flow
)

from scanner.correlation_engine import (
    correlate_behaviors
)

from scanner.behavioral_extractor import (
    extract_behavior
)


def main():

    result = parse_file(
    "pathlib_test.py"
)

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

    print("\n===== FLOWS =====\n")

    for flow in flows:

        print(flow)

    print("\n===== BEHAVIORS =====\n")

    for k, v in behaviors.items():

        print(f"{k}: {v}")

    print("\n===== FINDINGS =====\n")

    for finding in findings:

        print(finding)


if __name__ == "__main__":

    main()