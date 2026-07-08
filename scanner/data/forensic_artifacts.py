"""
forensic_artifacts.py
----------------------
Forensic artifact keywords for anti-forensics detection.
"""

FORENSIC_TARGET_KEYWORDS = {
    # Linux logs
    "history",
    "bash_history",
    ".bash_history",
    "zsh_history",
    ".zsh_history",
    "syslog",
    "auth.log",
    "secure",
    "messages",
    "faillog",
    "lastlog",
    "wtmp",
    "btmp",
    "journal",
    "audit",
    "audit.log",
    "auditd",
    
    # Windows logs
    "eventlog",
    "event_log",
    "security.evtx",
    "system.evtx",
    "application.evtx",
    "prefetch",
    "recent",
    
    # System artifacts
    "recycle",
    "temp",
    "tmp",
    "cache",
    "thumbcache",
    "memory.dmp",
    "core.dump",
}