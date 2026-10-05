"""
Common Password Detection Service
---------------------------------
Identifies passwords or substrings matching a safe, educational list of commonly used credentials.
NIST SP 800-63B mandates checking against known compromised or dictionary passwords.
"""
import os
from functools import lru_cache

COMMON_PASSWORDS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "common_passwords.txt"
)

@lru_cache(maxsize=1)
def load_common_passwords() -> set:
    """Load the safe educational common passwords list into memory."""
    passwords = set()
    if os.path.exists(COMMON_PASSWORDS_FILE):
        try:
            with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    cleaned = line.strip().lower()
                    if cleaned and not cleaned.startswith("#"):
                        passwords.add(cleaned)
        except Exception:
            pass
    # Fallback default common items if file reading fails
    if not passwords:
        passwords = {
            "password", "password123", "123456", "12345678", "qwerty",
            "letmein", "welcome", "admin", "admin123", "iloveyou"
        }
    return passwords

def is_common_password(password: str) -> dict:
    """
    Check if a password is an exact or base match against the common password dataset.

    Returns:
        dict: Findings, match classification, and scoring penalty.
    """
    if not password:
        return {
            "is_common": False,
            "match_type": "NONE",
            "matched_word": None,
            "penalty": 0,
            "description": "Password is empty."
        }

    common_set = load_common_passwords()
    lower_pwd = password.strip().lower()

    # 1. Exact match check
    if lower_pwd in common_set:
        return {
            "is_common": True,
            "match_type": "EXACT",
            "matched_word": lower_pwd,
            "penalty": -50,
            "severity": "CRITICAL",
            "description": (
                "Your password matches a commonly used password pattern and should not be used. "
                "Attackers use automated wordlists that test these within milliseconds."
            )
        }

    # 2. Substring match check (e.g., 'password123!', 'admin2026', 'qwerty@!')
    # Check for words in common_set of length >= 4 appearing inside the password
    for common_word in sorted(common_set, key=len, reverse=True):
        if len(common_word) >= 4 and common_word in lower_pwd:
            return {
                "is_common": True,
                "match_type": "SUBSTRING",
                "matched_word": common_word,
                "penalty": -25,
                "severity": "HIGH",
                "description": (
                    f"Password contains common word or pattern '{common_word}'. "
                    "Predictable dictionary words drastically simplify targeted dictionary attacks."
                )
            }

    return {
        "is_common": False,
        "match_type": "NONE",
        "matched_word": None,
        "penalty": 0,
        "severity": "NONE",
        "description": "Password does not match common dictionary or default credential lists."
    }
