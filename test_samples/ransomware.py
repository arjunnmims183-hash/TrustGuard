# test_samples/ransomware.py - Safe version (no actual encryption)
"""
Ransomware-like behavior simulation (SAFE - no actual encryption)
This is a test file for TrustGuard detection.
"""

import os

# Safe version - just simulates ransomware patterns
def encrypt_files():
    """SIMULATION: Does NOT actually encrypt files."""
    print("[SIMULATION] Ransomware behavior detected for testing purposes")
    
    # These patterns are what TrustGuard looks for:
    # - File read/write operations
    # - Potential encryption patterns
    # - Ransom note creation
    
    test_dir = os.path.expanduser('~/test_encrypt_safe')
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
        with open(os.path.join(test_dir, 'test.txt'), 'w') as f:
            f.write('Test content for TrustGuard detection')
    
    for root, dirs, files in os.walk(test_dir):
        for file in files:
            if file.endswith('.txt'):
                path = os.path.join(root, file)
                # Simulate reading (no actual encryption)
                with open(path, 'r') as f:
                    data = f.read()
                
                # Simulate writing (no actual encryption)
                with open(path + '.encrypted_sim', 'w') as f:
                    f.write(f"[SIMULATED ENCRYPTION] {data}")
    
    # Simulate ransom note
    with open(os.path.join(test_dir, 'README_DECRYPT.txt'), 'w') as f:
        f.write('SIMULATION: This is a test for TrustGuard detection.')

if __name__ == "__main__":
    encrypt_files()
    print("[SIMULATION] Test complete - no actual encryption performed")