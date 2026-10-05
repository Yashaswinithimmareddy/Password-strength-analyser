"""
Length Analyzer Service
-----------------------
Evaluates password length against modern defensive security standards (NIST SP 800-63B).
Awards length score contribution while explaining that length alone does not guarantee security.
"""

def analyze_length(password: str) -> dict:
    """
    Analyze the length of a password and return educational metrics and score points.

    Bands:
      - 0 to 7 chars: Very Short (High vulnerability to brute force)
      - 8 to 11 chars: Short (Marginal resistance, legacy minimum)
      - 12 to 15 chars: Better Length (Modern recommended minimum)
      - 16+ chars: Strong Length (Excellent search space contribution)

    Returns:
        dict: Structured length analysis metadata.
    """
    if password is None:
        password = ""

    length = len(password)

    if length == 0:
        return {
            "length": 0,
            "band": "EMPTY",
            "score_contribution": 0,
            "max_score": 35,
            "status": "FAIL",
            "description": "Password is empty. A secure password must have sufficient length.",
            "recommendation": "Provide a password of at least 12 to 16 characters or a memorable passphrase."
        }
    elif length < 8:
        # 1 to 7 chars: severely penalized
        score = min(10, length * 1.4)
        band = "VERY_SHORT"
        status = "CRITICAL"
        description = f"Password length is only {length} characters. This is critically short and vulnerable to immediate automated cracking."
    elif 8 <= length <= 11:
        # 8 to 11 chars: 12 to 22 points
        score = 12 + (length - 8) * 3
        band = "SHORT"
        status = "WARNING"
        description = f"Password length is {length} characters. While meeting legacy 8-character rules, modern attack rigs can exhaust this space quickly."
    elif 12 <= length <= 15:
        # 12 to 15 chars: 25 to 31 points
        score = 25 + (length - 12) * 2
        band = "MODERATE"
        status = "GOOD"
        description = f"Password length is {length} characters. Meets modern defensive recommendations (NIST SP 800-63B baseline)."
    else:
        # 16+ chars: max 35 points
        bonus = min(4, (length - 16) // 2)
        score = min(35, 31 + bonus)
        band = "STRONG"
        status = "EXCELLENT"
        description = f"Password length is {length} characters. Excellent length exponentially increases attacker search space."

    return {
        "length": length,
        "band": band,
        "score_contribution": round(score, 1),
        "max_score": 35,
        "status": status,
        "description": description,
        "educational_note": (
            "Length exponentially expands the theoretical search space (O(N^L)), "
            "but length alone cannot protect predictable inputs (e.g., 'aaaaaaaaaaaaaaaa')."
        )
    }
