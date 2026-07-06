from scanner.parser import parse_file
from scanner.source_sink_tracker import analyze_data_flow

result = parse_file("samples/test_flow_v3.py")

if result["error"]:
    print(result["error"])
    exit()

flows = analyze_data_flow(
    result["ast_tree"]
)

print("\nDetected Flows:\n")

for flow in flows:
    print(flow)