"""
Sequence Detector Service
-------------------------
Detects predictable ascending and descending character sequences (numeric and alphabetical).
Sequential patterns dramatically reduce search space because cracking algorithms prioritize sequential masks.
"""

def detect_sequences(password: str, min_length: int = 3) -> dict:
    """
    Detect ascending and descending numeric and alphabetical sequences.

    Examples:
      - 1234, 5678, 9876, 4321
      - abcd, efgh, dcba, zyxw

    Returns:
        dict: List of detected sequences, positions, penalty, and descriptions.
    """
    if not password or len(password) < min_length:
        return {
            "has_sequences": False,
            "sequences": [],
            "penalty": 0,
            "description": "No sequential patterns detected."
        }

    sequences_found = []
    lower = password.lower()
    n = len(lower)

    # Check numeric sequences
    i = 0
    while i < n - 1:
        # Ascending numeric
        if lower[i].isdigit() and lower[i+1].isdigit() and ord(lower[i+1]) - ord(lower[i]) == 1:
            start = i
            while i < n - 1 and lower[i+1].isdigit() and ord(lower[i+1]) - ord(lower[i]) == 1:
                i += 1
            length = i - start + 1
            if length >= min_length:
                seq_val = password[start:i+1]
                sequences_found.append({
                    "pattern": seq_val,
                    "type": "numeric_ascending",
                    "length": length,
                    "start": start
                })
        # Descending numeric
        elif lower[i].isdigit() and lower[i+1].isdigit() and ord(lower[i]) - ord(lower[i+1]) == 1:
            start = i
            while i < n - 1 and lower[i+1].isdigit() and ord(lower[i]) - ord(lower[i+1]) == 1:
                i += 1
            length = i - start + 1
            if length >= min_length:
                seq_val = password[start:i+1]
                sequences_found.append({
                    "pattern": seq_val,
                    "type": "numeric_descending",
                    "length": length,
                    "start": start
                })
        # Ascending alphabetical
        elif lower[i].isalpha() and lower[i+1].isalpha() and ord(lower[i+1]) - ord(lower[i]) == 1:
            start = i
            while i < n - 1 and lower[i+1].isalpha() and ord(lower[i+1]) - ord(lower[i]) == 1:
                i += 1
            length = i - start + 1
            if length >= min_length:
                seq_val = password[start:i+1]
                sequences_found.append({
                    "pattern": seq_val,
                    "type": "alpha_ascending",
                    "length": length,
                    "start": start
                })
        # Descending alphabetical
        elif lower[i].isalpha() and lower[i+1].isalpha() and ord(lower[i]) - ord(lower[i+1]) == 1:
            start = i
            while i < n - 1 and lower[i+1].isalpha() and ord(lower[i]) - ord(lower[i+1]) == 1:
                i += 1
            length = i - start + 1
            if length >= min_length:
                seq_val = password[start:i+1]
                sequences_found.append({
                    "pattern": seq_val,
                    "type": "alpha_descending",
                    "length": length,
                    "start": start
                })
        else:
            i += 1

    # Filter overlaps or duplicates
    unique_patterns = []
    seen = set()
    for s in sequences_found:
        if s["pattern"].lower() not in seen:
            seen.add(s["pattern"].lower())
            unique_patterns.append(s)

    has_sequences = len(unique_patterns) > 0
    penalty = -15 if has_sequences else 0

    description = "No sequential patterns detected."
    if has_sequences:
        seq_names = ", ".join(f"'{s['pattern']}' ({s['type'].replace('_', ' ')})" for s in unique_patterns)
        description = (
            f"Detected predictable sequence(s): {seq_names}. "
            "Sequential patterns are prioritized in brute-force mask attacks and reduce true security."
        )

    return {
        "has_sequences": has_sequences,
        "sequences": unique_patterns,
        "penalty": penalty,
        "severity": "WARNING" if has_sequences else "NONE",
        "description": description
    }
