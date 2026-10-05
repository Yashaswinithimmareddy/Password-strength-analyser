"""
Keyboard Walk and Spatial Pattern Detector Service
--------------------------------------------------
Detects physical keyboard layouts and spatial walks (QWERTY rows, numpad grids).
Users frequently generate keyboard walks (e.g., 'qwerty', 'asdf', 'zxcv')
because they feel effortless to type, but password auditing tools (e.g., Hashcat, John the Ripper)
explicitly pre-index keyboard walks.
"""

# QWERTY standard layout rows
KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

# Numpad layouts
NUMPAD_ROWS = [
    "789",
    "456",
    "123",
]
NUMPAD_COLS = [
    "741",
    "852",
    "963",
]
NUMPAD_DIAGS = [
    "753",
    "159",
    "951",
    "357",
]

def _build_spatial_substrings(min_len: int = 4) -> set:
    """Generate all contiguous substrings of keyboard rows and columns (forward & reverse)."""
    patterns = set()
    all_lines = list(KEYBOARD_ROWS) + NUMPAD_ROWS + NUMPAD_COLS + NUMPAD_DIAGS

    for line in all_lines:
        line_len = len(line)
        for length in range(min_len, min(line_len + 1, 8)):
            for start in range(line_len - length + 1):
                chunk = line[start:start + length]
                patterns.add(chunk)
                patterns.add(chunk[::-1]) # reverse walk (e.g., poiuy, lkjh)
    return patterns

SPATIAL_PATTERNS = _build_spatial_substrings(min_len=4)

def detect_keyboard_patterns(password: str) -> dict:
    """
    Detect keyboard walks and spatial patterns in password.

    Returns:
        dict: Findings, list of matched walks, penalty, and description.
    """
    if not password or len(password) < 4:
        return {
            "has_keyboard_patterns": False,
            "patterns": [],
            "penalty": 0,
            "description": "No keyboard walk patterns detected."
        }

    lower = password.lower()
    matches = []

    for pattern in sorted(SPATIAL_PATTERNS, key=len, reverse=True):
        if pattern in lower:
            # Check if this pattern is already covered by a longer match
            if not any(pattern in m for m in matches):
                matches.append(pattern)

    has_patterns = len(matches) > 0
    penalty = -15 if has_patterns else 0

    description = "No keyboard walk patterns detected."
    if has_patterns:
        match_str = ", ".join(f"'{m}'" for m in matches)
        description = (
            f"Detected keyboard walk pattern(s): {match_str}. "
            "Spatial walks are predictable physical patterns that attackers test early in dictionary/rule attacks."
        )

    return {
        "has_keyboard_patterns": has_patterns,
        "patterns": matches,
        "penalty": penalty,
        "severity": "WARNING" if has_patterns else "NONE",
        "description": description
    }
