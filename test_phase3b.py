import sys

from scanner.parser import parse_file
from scanner.source_sink_tracker import analyze_data_flow
from scanner.attack_scorer import AttackScorer

if len(sys.argv) != 2:
    print(
        "Usage: python test_phase3b.py <sample.py>"
    )
    exit()

filename = sys.argv[1]

result = parse_file(filename)

flows = analyze_data_flow(
    result["ast_tree"]
)

scorer = AttackScorer()

for flow in flows:

    print("\nFLOW:")
    print(flow)

    print("\nSCORE:")
    print(
        scorer.score_flow(flow)
    )   