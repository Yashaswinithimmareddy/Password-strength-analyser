"""
Contextual Personal Information Checker Service
------------------------------------------------
OPTIONAL DEFENSIVE CHECK: Detects if user-provided demographic context
(first name, birth year, organization/college) is embedded in the password.

CRITICAL PRIVACY RULE:
This data is processed transiently strictly in volatile memory.
It is NEVER persisted, logged, or sent to external endpoints.
"""
import re

LEET_MAP = {
    "@": "a", "4": "a",
    "8": "b",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "5": "s", "$": "s",
    "7": "t", "+": "t"
}

def _de_leet(text: str) -> str:
    """Normalize common leetspeak substitutions back to Latin characters."""
    out = []
    for ch in text.lower():
        out.append(LEET_MAP.get(ch, ch))
    return "".join(out)

def check_personal_context(password: str, context: dict = None) -> dict:
    """
    Check if user-volunteered context overlaps with the password.

    Supported context fields:
      - first_name (str)
      - birth_year (str or int)
      - organization (str - e.g., college, workplace)

    Returns:
        dict: Findings, matched items, penalty, description.
    """
    if not password or not context:
        return {
            "has_context_overlap": False,
            "matched_fields": [],
            "penalty": 0,
            "description": "No personal context provided or checked."
        }

    pwd_lower = password.lower()
    pwd_deleet = _de_leet(password)
    matched_fields = []

    # 1. First Name check (minimum 3 characters)
    first_name = str(context.get("first_name", "")).strip().lower()
    if len(first_name) >= 3:
        if first_name in pwd_lower or first_name in pwd_deleet:
            matched_fields.append({
                "field": "First Name",
                "matched_value": first_name[0] + "*" * (len(first_name) - 1), # Redacted for safety
                "description": "Password embeds user's first name (or leetspeak variation)."
            })

    # 2. Birth Year check (4-digit year like 1990-2029)
    birth_year = str(context.get("birth_year", "")).strip()
    if birth_year and len(birth_year) == 4 and birth_year.isdigit():
        if birth_year in pwd_lower:
            matched_fields.append({
                "field": "Birth Year",
                "matched_value": "****",
                "description": "Password embeds user's birth year."
            })

    # 3. Organization or College Name check
    organization = str(context.get("organization", "")).strip().lower()
    if len(organization) >= 3:
        if organization in pwd_lower or organization in pwd_deleet:
            matched_fields.append({
                "field": "Organization / College",
                "matched_value": organization[0] + "*" * (len(organization) - 1),
                "description": "Password embeds company, school, or organization name."
            })

    has_overlap = len(matched_fields) > 0
    penalty = -25 if has_overlap else 0

    description = "No personal context overlap detected."
    if has_overlap:
        names = ", ".join(f"{m['field']}" for m in matched_fields)
        description = (
            f"Password appears to contain personal information ({names}). "
            "Attackers routinely mine public social profiles (OSINT) to build custom targeted wordlists."
        )

    return {
        "has_context_overlap": has_overlap,
        "matched_fields": matched_fields,
        "penalty": penalty,
        "severity": "CRITICAL" if has_overlap else "NONE",
        "description": description
    }
