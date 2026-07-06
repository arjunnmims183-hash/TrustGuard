from scanner.parser import parse_file
from scanner.source_sink_tracker import analyze_data_flow


def main():

    result = parse_file(
        "samples/test_flow_v2.py"
    )

    if result["error"]:
        print(result["error"])
        return

    flows = analyze_data_flow(
        result["ast_tree"]
    )

    print("\nDetected Flows:\n")

    for flow in flows:
        print(flow)


if __name__ == "__main__":
    main()