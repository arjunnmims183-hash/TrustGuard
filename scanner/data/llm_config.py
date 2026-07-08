"""
llm_config.py
--------------
Configuration for Phase 4 LLM integration.
"""

# ==========================================
# OLLAMA CONFIGURATION
# ==========================================

OLLAMA_CONFIG = {
    "host": "http://localhost:11434",
    "model": "llama3.1:latest",  # ✅ Updated to your installed model
    "temperature": 0.3,
    "max_tokens": 500,
    "timeout": 120,
}

# Alternative models you can use
ALTERNATIVE_MODELS = {
    "llama3.1": "llama3.1:latest",
    "llama3.2": "llama3.2:3b",
    "mistral": "mistral:7b",
    "qwen2.5": "qwen2.5:7b",
    "phi3": "phi3:mini",
    "gemma2": "gemma2:2b",
}

# ==========================================
# ENABLE/DISABLE LLM
# ==========================================

LLM_ENABLED = True
USE_LOCAL_LLM = True

# ==========================================
# INTENT COMPARISON CONFIG
# ==========================================

INTENT_CATEGORIES = {
    "backup": ["backup", "restore", "archive", "snapshot", "save"],
    "network": ["network", "connect", "send", "receive", "download", "upload"],
    "file": ["file", "read", "write", "open", "close", "create", "delete"],
    "system": ["system", "command", "execute", "process", "shell"],
    "credential": ["credential", "password", "secret", "token", "key", "auth"],
    "encryption": ["encrypt", "decrypt", "crypto", "cipher"],
}

# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "OLLAMA_CONFIG",
    "ALTERNATIVE_MODELS",
    "LLM_ENABLED",
    "USE_LOCAL_LLM",
    "INTENT_CATEGORIES",
]