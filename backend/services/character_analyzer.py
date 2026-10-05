"""
Character Diversity Analyzer Service
-----------------------------------
Evaluates character composition, variety, and uniqueness ratios.
Explains why character diversity increases the alphabet pool N,
while demonstrating why diversity alone (e.g., 'Password123!') fails to guarantee security.
"""
import string

def analyze_characters(password: str) -> dict:
    """
    Analyze the character distribution, diversity categories, and uniqueness ratio.

    Returns:
        dict: Breakdown of character types, counts, unique ratios, and score contributions.
    """
    if not password:
        return {
            "has_lowercase": False,
            "has_uppercase": False,
            "has_digits": False,
            "has_symbols": False,
            "has_spaces": False,
            "lowercase_count": 0,
            "uppercase_count": 0,
            "digit_count": 0,
            "symbol_count": 0,
            "space_count": 0,
            "character_type_count": 0,
            "unique_character_count": 0,
            "unique_character_ratio": 0.0,
            "diversity_score": 0,
            "uniqueness_score": 0,
            "total_score_contribution": 0,
            "max_score": 25,
            "educational_note": "No characters detected."
        }

    length = len(password)
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_spaces = any(c.isspace() for c in password)
    # Symbols include punctuation and special printable ASCII characters
    has_symbols = any(c in string.punctuation or (not c.isalnum() and not c.isspace()) for c in password)

    lowercase_count = sum(1 for c in password if c.islower())
    uppercase_count = sum(1 for c in password if c.isupper())
    digit_count = sum(1 for c in password if c.isdigit())
    space_count = sum(1 for c in password if c.isspace())
    symbol_count = sum(1 for c in password if (c in string.punctuation or (not c.isalnum() and not c.isspace())))

    # Count distinct character classes (max 5: lower, upper, digit, symbol, space)
    classes_present = [has_lowercase, has_uppercase, has_digits, has_symbols, has_spaces]
    character_type_count = sum(1 for present in classes_present if present)

    unique_chars = set(password)
    unique_character_count = len(unique_chars)
    unique_character_ratio = round(unique_character_count / length, 3)

    # Diversity score (up to 15 points)
    # 1 class: 2 pts, 2 classes: 5 pts, 3 classes: 10 pts, 4+ classes: 15 pts
    if character_type_count <= 1:
        diversity_score = 2
    elif character_type_count == 2:
        diversity_score = 6
    elif character_type_count == 3:
        diversity_score = 11
    else:
        diversity_score = 15

    # Uniqueness score (up to 10 points based on ratio)
    # Low ratio (<0.3) implies heavy repetition (e.g., 'aaaaaaaa')
    if unique_character_ratio >= 0.80:
        uniqueness_score = 10
    elif unique_character_ratio >= 0.60:
        uniqueness_score = 7
    elif unique_character_ratio >= 0.40:
        uniqueness_score = 4
    elif unique_character_ratio >= 0.25:
        uniqueness_score = 2
    else:
        uniqueness_score = 0

    total_score = diversity_score + uniqueness_score

    return {
        "has_lowercase": has_lowercase,
        "has_uppercase": has_uppercase,
        "has_digits": has_digits,
        "has_symbols": has_symbols,
        "has_spaces": has_spaces,
        "lowercase_count": lowercase_count,
        "uppercase_count": uppercase_count,
        "digit_count": digit_count,
        "symbol_count": symbol_count,
        "space_count": space_count,
        "character_type_count": character_type_count,
        "unique_character_count": unique_character_count,
        "unique_character_ratio": unique_character_ratio,
        "diversity_score": diversity_score,
        "uniqueness_score": uniqueness_score,
        "total_score_contribution": total_score,
        "max_score": 25,
        "educational_note": (
            "Character variety expands character pool size N, but predictable combinations "
            "(e.g., uppercase first letter, digits, symbol at the end: 'Password123!') "
            "are prioritized by modern attacker rule-based mask attacks."
        )
    }
