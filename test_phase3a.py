from scanner.parser import parse_file
from scanner.source_sink_tracker import analyze_data_flow

from scanner.attack_graph import (
    build_attack_graph,
    print_graph
)

result = parse_file(
    "test_full_pipeline.py"
)

flows = analyze_data_flow(
    result["ast_tree"]
)

graph = build_attack_graph(
    flows
)

print_graph(graph)  