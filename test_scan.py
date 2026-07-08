"""
test_scan.py - Comprehensive test suite for scan.py
"""

import sys
import os
import json
import subprocess
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ============================================================================
# Force UTF-8 encoding for Windows console
# ============================================================================
if sys.platform == 'win32':
    try:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    except (AttributeError, ValueError):
        pass

# ============================================================================
# Simple ASCII Print Functions (no Unicode/ANSI colors)
# ============================================================================

def print_header(text):
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"{text}")
    print(f"{'='*60}")

def print_success(text):
    """Print a success message."""
    print(f"[PASS] {text}")

def print_failure(text):
    """Print a failure message."""
    print(f"[FAIL] {text}")

def print_info(text):
    """Print an info message."""
    print(f"[INFO] {text}")

def print_warning(text):
    """Print a warning message."""
    print(f"[WARN] {text}")


# ============================================================================
# Test Functions
# ============================================================================

def run_scan_test(filepath, expected_score_range=None, expected_findings=None):
    """
    Run scan.py on a file and validate results.
    
    Args:
        filepath: Path to test file
        expected_score_range: Tuple of (min_score, max_score)
        expected_findings: List of expected finding types
    """
    print_info(f"Testing: {filepath}")
    
    # Run scan.py as subprocess with JSON output
    try:
        result = subprocess.run(
            [sys.executable, 'scan.py', filepath, '--json'],
            capture_output=True,
            text=True,
            timeout=30
        )
    except subprocess.TimeoutExpired:
        print_failure(f"Timeout: {filepath}")
        return False
    
    # Check if scan succeeded
    if result.returncode not in [0, 1]:  # 1 is for high risk (expected for malicious)
        print_failure(f"Scan failed with code {result.returncode}")
        if result.stderr:
            print(f"STDERR: {result.stderr[:200]}")
        return False
    
    # Find JSON output file
    json_file = filepath.replace('.py', '_trustguard.json')
    if not os.path.exists(json_file):
        print_failure(f"JSON file not found: {json_file}")
        if result.stdout:
            # Show last few lines of output
            lines = result.stdout.strip().split('\n')
            for line in lines[-5:]:
                print(f"  {line}")
        return False
    
    # Load JSON results
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print_failure(f"Failed to parse JSON: {e}")
        return False
    
    # Clean up JSON file
    try:
        os.remove(json_file)
    except:
        pass
    
    # Validate results
    passed = True
    
    # Check score
    if expected_score_range:
        score = data.get('score', 0)
        if isinstance(score, dict):
            score = score.get('threat_score', score.get('total', 0))
        elif isinstance(score, (int, float)):
            score = int(score)
        else:
            score = 0
            
        min_score, max_score = expected_score_range
        if not (min_score <= score <= max_score):
            print_failure(f"Score {score} not in range [{min_score}-{max_score}]")
            passed = False
        else:
            print_success(f"Score: {score} (expected {min_score}-{max_score})")
    
    # Check findings
    if expected_findings:
        # Try both structured and flat formats
        findings = data.get('phase3', {}).get('correlation_findings', [])
        if not findings:
            findings = data.get('correlation_findings', [])
        
        finding_types = [f.get('attack_type', '') for f in findings]
        
        for expected in expected_findings:
            if expected in finding_types:
                print_success(f"Found: {expected}")
            else:
                print_failure(f"Missing: {expected}")
                passed = False
    
    return passed


def test_basic_functionality():
    """Test basic scan.py functionality."""
    print_header("Basic Functionality Tests")
    
    all_passed = True
    
    # Test 1: Help menu
    print_info("Testing: --help")
    result = subprocess.run(
        [sys.executable, 'scan.py', '--help'],
        capture_output=True,
        text=True
    )
    if result.returncode == 0 and ('usage:' in result.stdout or 'TrustGuard' in result.stdout):
        print_success("Help menu works")
    else:
        print_failure("Help menu failed")
        all_passed = False
    
    # Test 2: Version
    print_info("Testing: --version")
    result = subprocess.run(
        [sys.executable, 'scan.py', '--version'],
        capture_output=True,
        text=True
    )
    if result.returncode == 0 and ('TrustGuard' in result.stdout or '3.0' in result.stdout):
        print_success("Version works")
    else:
        print_failure("Version failed")
        all_passed = False
    
    return all_passed


def test_all_samples():
    """Test all sample files."""
    print_header("Sample File Tests")
    
    sample_dir = 'test_samples'
    if not os.path.exists(sample_dir):
        print_warning(f"Directory {sample_dir} not found")
        print_info("Creating test_samples directory...")
        os.makedirs(sample_dir, exist_ok=True)
        print_failure(f"Please create test files in {sample_dir}/")
        return False
    
    # Test definitions: (filename, (min_score, max_score), expected_findings)
    tests = [
        ('clean.py', (0, 20), []),
        ('credential_theft.py', (80, 100), ['OBFUSCATED_CREDENTIAL_EXFILTRATION']),
        ('pathlib_operations.py', (0, 30), []),
        ('backdoor.py', (80, 100), []),
        ('ransomware.py', (0, 50), []),
    ]
    
    all_passed = True
    
    for filename, score_range, findings in tests:
        filepath = os.path.join(sample_dir, filename)
        if not os.path.exists(filepath):
            print_warning(f"Skipping {filename} (file not found)")
            continue
        
        passed = run_scan_test(filepath, score_range, findings)
        if not passed:
            all_passed = False
    
    return all_passed


def test_structured_output():
    """Test that structured output format is correct."""
    print_header("Structured Output Tests")
    
    filepath = 'test_samples/credential_theft.py'
    if not os.path.exists(filepath):
        print_warning(f"Skipping: {filepath} not found")
        return True
    
    # Run scan
    subprocess.run(
        [sys.executable, 'scan.py', filepath, '--json'],
        capture_output=True,
        text=True
    )
    
    json_file = filepath.replace('.py', '_trustguard.json')
    if not os.path.exists(json_file):
        print_failure("JSON file not found")
        return False
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print_failure(f"Failed to parse JSON: {e}")
        return False
    
    try:
        os.remove(json_file)
    except:
        pass
    
    passed = True
    
    # Check metadata
    if 'metadata' not in data:
        print_failure("Missing 'metadata' key")
        passed = False
    else:
        print_success("metadata present")
        if data['metadata'].get('version') == '3.0':
            print_success("version: 3.0")
        else:
            print_failure(f"version: {data['metadata'].get('version')} (expected 3.0)")
            passed = False
    
    # Check phase keys
    for phase in ['phase1', 'phase2', 'phase3']:
        if phase not in data:
            print_failure(f"Missing '{phase}' key")
            passed = False
        else:
            print_success(f"{phase} present")
    
    # Check score is dict
    score = data.get('score')
    if isinstance(score, dict):
        print_success("score is dict")
        if 'threat_score' in score:
            print_success("score has threat_score")
        if 'risk_level' in score:
            print_success("score has risk_level")
    else:
        print_failure(f"score is not dict (type: {type(score).__name__})")
        passed = False
    
    return passed


def test_malformed_input():
    """Test error handling with malformed input."""
    print_header("Error Handling Tests")
    
    all_passed = True
    
    # Test non-existent file
    print_info("Testing: non-existent file")
    result = subprocess.run(
        [sys.executable, 'scan.py', 'does_not_exist.py'],
        capture_output=True,
        text=True
    )
    # ✅ Check if it fails (non-zero exit code)
    if result.returncode != 0:
        print_success(f"Non-existent file handled (exit code: {result.returncode})")
    else:
        print_failure("Non-existent file did not return error (exit code: 0)")
        all_passed = False
    
    # Test invalid Python syntax
    print_info("Testing: invalid Python syntax")
    with open('test_invalid.py', 'w', encoding='utf-8') as f:
        f.write("def broken_function(:\n    pass\n")
    
    result = subprocess.run(
        [sys.executable, 'scan.py', 'test_invalid.py'],
        capture_output=True,
        text=True
    )
    try:
        os.remove('test_invalid.py')
    except:
        pass
    
    # ✅ Check if it fails (non-zero exit code)
    if result.returncode != 0:
        print_success(f"Invalid syntax handled (exit code: {result.returncode})")
    else:
        print_failure("Invalid syntax did not return error (exit code: 0)")
        all_passed = False
    
    return all_passed


def test_backward_compatibility():
    """Test backward compatibility with flat keys."""
    print_header("Backward Compatibility Tests")
    
    filepath = 'test_samples/credential_theft.py'
    if not os.path.exists(filepath):
        print_warning(f"Skipping: {filepath} not found")
        return True
    
    # Run scan
    subprocess.run(
        [sys.executable, 'scan.py', filepath, '--json'],
        capture_output=True,
        text=True
    )
    
    json_file = filepath.replace('.py', '_trustguard.json')
    if not os.path.exists(json_file):
        print_failure("JSON file not found")
        return False
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print_failure(f"Failed to parse JSON: {e}")
        return False
    
    try:
        os.remove(json_file)
    except:
        pass
    
    passed = True
    
    # Test legacy keys exist
    legacy_keys = ['dangerous_apis', 'secrets', 'feature_vector', 'data_flows', 'correlation_findings']
    for key in legacy_keys:
        if key in data:
            print_success(f"legacy key: {key} present")
        else:
            print_failure(f"Missing legacy key: '{key}'")
            passed = False
    
    # Test that phase data matches legacy data
    phase1_dangerous = data.get('phase1', {}).get('dangerous_apis', [])
    flat_dangerous = data.get('dangerous_apis', [])
    if phase1_dangerous == flat_dangerous:
        print_success("Phase1 and flat dangerous_apis match")
    else:
        print_failure("Phase1 and flat dangerous_apis mismatch")
        passed = False
    
    return passed


def main():
    """Run all tests."""
    print_header("TrustGuard scan.py Test Suite")
    print_info(f"Python: {sys.executable}")
    print_info(f"Version: {sys.version}")
    
    # Check if scan.py exists
    if not os.path.exists('scan.py'):
        print_failure("scan.py not found in current directory")
        print_info("Please run this from the trustguard root directory")
        return 1
    
    all_passed = True
    
    # Run tests
    if not test_basic_functionality():
        all_passed = False
        print_warning("Basic functionality tests failed")
    
    if not test_all_samples():
        all_passed = False
        print_warning("Sample file tests failed")
    
    if not test_structured_output():
        all_passed = False
        print_warning("Structured output tests failed")
    
    if not test_malformed_input():
        all_passed = False
        print_warning("Error handling tests failed")
    
    if not test_backward_compatibility():
        all_passed = False
        print_warning("Backward compatibility tests failed")
    
    # Final summary
    print_header("Test Summary")
    if all_passed:
        print_success("ALL TESTS PASSED!")
        print_info("The refactored scan.py is ready for production.")
        return 0
    else:
        print_failure("SOME TESTS FAILED")
        print_info("Please fix the issues before moving on.")
        return 1


if __name__ == "__main__":
    sys.exit(main())