"""
sensitive_sources.py
--------------------
Sensitive environment variable and credential patterns.
"""

SUSPICIOUS_ENV = {
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "TOKEN",
    "PASSWORD",
    "SECRET",
    "API_KEY",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "JWT_SECRET",
    "OAUTH_TOKEN",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "CLIENT_SECRET",
    "DATABASE_URL",
    "REDIS_URL",
    "AZURE_CLIENT_SECRET",
    "GCP_CLIENT_SECRET",
}

SENSITIVE_STRINGS = {
    "password",
    "secret",
    "token",
    "api_key",
    "private_key",
    "credentials",
    "auth",
}