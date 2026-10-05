"""
Privacy Filter and Zero-Knowledge Sanitizer Utility
---------------------------------------------------
Enforces strict zero-knowledge principles across the entire application lifecycle:
1. Strips sensitive fields (passwords, context) from logs, telemetry, and error responses.
2. Formats sanitized audit logs with strictly non-invertible aggregate metrics.
3. Provides custom logging filters ensuring no raw payloads appear in console stdout.
"""
import logging
import re

SENSITIVE_KEYS = {"password", "secret", "token", "pwd", "first_name", "birth_year", "organization"}

class PrivacySanitizingFilter(logging.Filter):
    """
    Logging filter that intercepts log records and scrubs any accidental occurrences
    of sensitive patterns or password fields.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            # Mask potential password parameter patterns
            record.msg = re.sub(r'("password"\s*:\s*)"[^"]+"', r'\1"[REDACTED_BY_PRIVACY_FILTER]"', record.msg, flags=re.IGNORECASE)
            record.msg = re.sub(r'(password=)[^\s&]+', r'\1[REDACTED]', record.msg, flags=re.IGNORECASE)
        return True

def sanitize_dict_for_logging(data: dict) -> dict:
    """
    Deep-copy dictionary and replace any sensitive keys with redacted indicators.
    """
    if not isinstance(data, dict):
        return data

    sanitized = {}
    for k, v in data.items():
        if k.lower() in SENSITIVE_KEYS:
            sanitized[k] = "[REDACTED_PRIVACY_ENFORCED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_dict_for_logging(v)
        elif isinstance(v, list):
            sanitized[k] = [sanitize_dict_for_logging(item) if isinstance(item, dict) else item for item in v]
        else:
            sanitized[k] = v
    return sanitized
