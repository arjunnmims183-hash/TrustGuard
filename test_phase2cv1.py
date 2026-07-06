from scanner.parser import parse_file

from scanner.source_sink_tracker import (
    analyze_data_flow
)

from scanner.correlation_engine import (
    analyze_flows
)


def main():

    result = parse_file(
    "samples/test_phase2b_complete.py"
)

    if result["error"]:

        print(
            result["error"]
        )

        return

    flows = analyze_data_flow(
        result["ast_tree"]
    )

    print(
        "\n===== FLOWS =====\n"
    )

    for flow in flows:

        print(flow)

    findings = analyze_flows(
        flows
    )

    print(
        "\n===== FINDINGS =====\n"
    )

    for finding in findings:

        print(finding)


if __name__ == "__main__":

    main()