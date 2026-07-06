from scanner.parser import parse_file
from scanner.source_sink_tracker import analyze_data_flow

parsed = parse_file("test_flow.py")

flows = analyze_data_flow(
    parsed["ast_tree"]
)

print("\nDetected Flows:\n")

for flow in flows:
    print(flow)