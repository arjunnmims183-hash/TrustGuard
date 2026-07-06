from scanner.parser import parse_file
from scanner.behavioral_extractor import extract_behavior

parsed = parse_file("test_sample.py")

features = extract_behavior(
    parsed["ast_tree"],
    parsed["source"]
)

print("\nBehavior Features:")
for key, value in features.items():
    print(f"{key}: {value}")