from scanner.parser import parse_file
from scanner.source_sink_tracker import analyze_data_flow


def main():

    result = parse_file(
        "samples/test_phase2b_complete.py"
    )

    if result["error"]:
        print(result["error"])
        return

    print("\n===== PARSER OUTPUT =====\n")

    print("Imports:")
    print(result["imports"])

    print("\nCalls:")

    for call in result["calls"]:
        print(call)

    print(
        "\n===== DATA FLOW ANALYSIS =====\n"
    )

    flows = analyze_data_flow(
        result["ast_tree"]
    )

    print(
        "\n===== FINAL FLOWS =====\n"
    )

    for flow in flows:
        print(flow)


if __name__ == "__main__":
    main()