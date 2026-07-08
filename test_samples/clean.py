# clean.py - Benign code with no suspicious behavior
import os
import json

def read_config():
    with open('config.json', 'r') as f:
        return json.load(f)

def process_data(data):
    result = []
    for item in data:
        result.append(item.strip().lower())
    return result

def main():
    config = read_config()
    data = ['Hello', 'World']
    processed = process_data(data)
    print(processed)

if __name__ == "__main__":
    main()