"""
Pattern Detector Engine
-----------------------
Aggregates sequence detection, keyboard walk detection, repetition detection,
and structural predictable patterns (e.g., Word + Number, Word + Year, Prefix/Suffix).
"""
import re
from .sequence_detector import detect_sequences
from .keyboard_detector import detect_keyboard_patterns
from .repetition_detector import detect_repetition

YEAR_REGEX = re.compile(r"(19\d{2}|20[0-3]\d)")
WORD_PLUS_NUMBER_REGEX = re.compile(r"^[A-Za-z]+[0-9]+[!@#$%^&*()_+=-]?$")
STANDARD_COMPOSITION_REGEX = re.compile(r"^[A-Z][a-z]+[0-9]+[!@#$%^&*()_+=-]$")

def detect_predictable_structure(password: str) -> dict:
    """
    Detect predictable structural habits (e.g., 'Word + Number', 'Capitalized + digits + symbol').
    Explains why passwords like 'Password123!' or 'Welcome2026!' fail defensive posture.
    """
    if not password:
        return {"has_predictable_structure": False, "patterns": [], "penalty": 0, "description": ""}

    patterns = []
    penalty = 0

    # 1. Year pattern (e.g. 1995, 2024, 2025, 2026)
    year_matches = YEAR_REGEX.findall(password)
    if year_matches:
        patterns.append({
            "type": "year_pattern",
            "detected": year_matches,
            "description": f"Contains year-like 4-digit sequence ({', '.join(year_matches)})."
        })
        penalty -= 10

    # 2. Standard corporate composition habit: Single Capital letter, lower letters, digits, single symbol at end
    # e.g., 'Password123!' or 'Welcome2025#'
    if STANDARD_COMPOSITION_REGEX.match(password):
        patterns.append({
            "type": "predictable_formula",
            "detected": "Capital + lowercase + numbers + symbol",
            "description": "Matches the ubiquitous 'Capital + word + digits + symbol' corporate formula heavily targeted by cracking masks."
        })
        penalty -= 15
    elif WORD_PLUS_NUMBER_REGEX.match(password):
        patterns.append({
            "type": "word_plus_digits",
            "detected": "Word followed by digits",
            "description": "Contains simple predictable dictionary word followed by digits."
        })
        penalty -= 10

    has_structure = len(patterns) > 0
    desc = "; ".join(p["description"] for p in patterns) if has_structure else "No predictable structural formula detected."

    return {
        "has_predictable_structure": has_structure,
        "patterns": patterns,
        "penalty": penalty,
        "description": desc
    }

def detect_all_patterns(password: str) -> dict:
    """
    Run the complete suite of defensive pattern analyzers against the password.

    Returns:
        dict: Consolidated pattern findings, total pattern penalties, and descriptive alerts.
    """
    seq_res = detect_sequences(password)
    kbd_res = detect_keyboard_patterns(password)
    rep_res = detect_repetition(password)
    struct_res = detect_predictable_structure(password)

    findings = []
    total_penalty = 0

    if seq_res["has_sequences"]:
        total_penalty += seq_res["penalty"]
        findings.append({
            "category": "SEQUENCE",
            "severity": seq_res["severity"],
            "description": seq_res["description"],
            "details": seq_res["sequences"]
        })

    if kbd_res["has_keyboard_patterns"]:
        total_penalty += kbd_res["penalty"]
        findings.append({
            "category": "KEYBOARD_WALK",
            "severity": kbd_res["severity"],
            "description": kbd_res["description"],
            "details": kbd_res["patterns"]
        })

    if rep_res["has_repetition"]:
        total_penalty += rep_res["penalty"]
        findings.append({
            "category": "REPETITION",
            "severity": rep_res["severity"],
            "description": rep_res["description"],
            "details": {
                "chars": rep_res["repeated_characters"],
                "substrings": rep_res["repeated_substrings"]
            }
        })

    if struct_res["has_predictable_structure"]:
        total_penalty += struct_res["penalty"]
        findings.append({
            "category": "PREDICTABLE_STRUCTURE",
            "severity": "WARNING",
            "description": struct_res["description"],
            "details": struct_res["patterns"]
        })

    # Cap total pattern penalty at -40 to prevent negative runaway
    total_penalty = max(-40, total_penalty)

    return {
        "pattern_count": len(findings),
        "total_penalty": total_penalty,
        "findings": findings,
        "has_any_pattern": len(findings) > 0,
        "sequence_analysis": seq_res,
        "keyboard_analysis": kbd_res,
        "repetition_analysis": rep_res,
        "structure_analysis": struct_res
    }
