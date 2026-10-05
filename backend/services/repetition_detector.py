"""
Repetition Detector Service
---------------------------
Detects consecutive identical characters ('aaaa', '1111')
and repeating chunk patterns ('ababab', 'abcabcabc', 'passpass').
Repeated symbols decrease effective entropy to near zero despite long character lengths.
"""
import re

def detect_repetition(password: str) -> dict:
    """
    Analyze passwords for consecutive character repetitions and repeating substrings.

    Returns:
        dict: Findings, repeated characters, repeated substrings, penalty, and description.
    """
    if not password or len(password) < 3:
        return {
            "has_repetition": False,
            "repeated_characters": [],
            "repeated_substrings": [],
            "penalty": 0,
            "description": "No repetitive patterns detected."
        }

    repeated_chars = []
    repeated_substrings = []

    # 1. Consecutive identical characters (e.g., 'aaaa', '1111', 'ZZZZ')
    char_repeat_matches = re.finditer(r"(.)\1{2,}", password, re.IGNORECASE)
    for match in char_repeat_matches:
        full = match.group(0)
        repeated_chars.append({
            "character": full[0],
            "full_match": full,
            "count": len(full),
            "start": match.start()
        })

    # 2. Repeating substrings (length 2 to 6, repeating 2 or more times)
    # e.g., 'ababab', 'abcabc', 'passpass'
    lower = password.lower()
    n = len(lower)
    for chunk_size in range(2, min(7, n // 2 + 1)):
        for i in range(n - chunk_size * 2 + 1):
            chunk = lower[i:i + chunk_size]
            # See how many consecutive repetitions occur
            reps = 1
            idx = i + chunk_size
            while idx + chunk_size <= n and lower[idx:idx + chunk_size] == chunk:
                reps += 1
                idx += chunk_size
            if reps >= 2:
                pattern_str = lower[i:i + reps * chunk_size]
                if not any(pattern_str in existing["pattern"] for existing in repeated_substrings):
                    repeated_substrings.append({
                        "chunk": chunk,
                        "repetitions": reps,
                        "pattern": pattern_str,
                        "length": reps * chunk_size
                    })

    has_char_repeat = len(repeated_chars) > 0
    has_sub_repeat = len(repeated_substrings) > 0
    has_repetition = has_char_repeat or has_sub_repeat

    # Calculate penalty
    penalty = 0
    if has_char_repeat:
        # Severe penalty if single char dominates whole password
        longest_rep = max(c["count"] for c in repeated_chars)
        if longest_rep >= 6 or (longest_rep / len(password)) >= 0.5:
            penalty -= 25
        else:
            penalty -= 15

    if has_sub_repeat and penalty > -25:
        penalty = min(penalty, -20)

    description = "No repetitive patterns detected."
    if has_repetition:
        notes = []
        if repeated_chars:
            notes.append(", ".join(f"'{c['full_match']}' ({c['count']}x '{c['character']}')" for c in repeated_chars))
        if repeated_substrings:
            notes.append(", ".join(f"'{s['pattern']}' ({s['repetitions']}x '{s['chunk']}')" for s in repeated_substrings))
        description = (
            f"Detected repetitive patterns: {'; '.join(notes)}. "
            "Repetitions offer trivial resistance against pattern-aware cracking engines."
        )

    return {
        "has_repetition": has_repetition,
        "repeated_characters": repeated_chars,
        "repeated_substrings": repeated_substrings,
        "penalty": penalty,
        "severity": "CRITICAL" if penalty <= -20 else ("WARNING" if has_repetition else "NONE"),
        "description": description
    }
