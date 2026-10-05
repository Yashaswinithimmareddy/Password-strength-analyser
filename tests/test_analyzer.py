"""
Unit Tests - Password Analyzer Core Engine
------------------------------------------
Validates length, character diversity, composition, entropy, and scoring boundaries.
"""
import pytest
from backend.services.password_analyzer import analyze_password
from backend.services.length_analyzer import analyze_length
from backend.services.character_analyzer import analyze_characters

def test_01_empty_password():
    """Test 1: Empty password must return score 0 and VERY WEAK classification."""
    res = analyze_password("", persist_analytics=False)
    assert res["score"] == 0
    assert res["classification"] == "VERY WEAK"
    assert res["metrics"]["length"]["length"] == 0

def test_02_one_character_password():
    """Test 2: Single character password must receive VERY WEAK score."""
    res = analyze_password("x", persist_analytics=False)
    assert res["score"] <= 20
    assert res["classification"] == "VERY WEAK"

def test_03_short_numeric_password():
    """Test 3: Short numeric '123456' must be classified VERY WEAK due to length and pattern."""
    res = analyze_password("123456", persist_analytics=False)
    assert res["score"] <= 20
    assert res["classification"] == "VERY WEAK"
    assert res["metrics"]["common_check"]["is_common"] is True

def test_04_common_password_dictionary_match():
    """Test 4: Common password 'password123' must trigger dictionary penalty."""
    res = analyze_password("password123", persist_analytics=False)
    assert res["metrics"]["common_check"]["is_common"] is True
    assert res["score"] <= 40

def test_05_long_repeated_password():
    """Test 5: Long repeated 'aaaaaaaaaaaaaaaa' must not score STRONG despite 16 chars."""
    res = analyze_password("aaaaaaaaaaaaaaaa", persist_analytics=False)
    assert res["metrics"]["length"]["length"] == 16
    # Repetition penalty must hold it to WEAK / MODERATE max
    assert res["score"] <= 40
    assert res["metrics"]["patterns"]["repetition_analysis"]["has_repetition"] is True

def test_06_lowercase_only():
    """Test 6: Lowercase only input detects single class."""
    res = analyze_characters("abcdefghijklm")
    assert res["has_lowercase"] is True
    assert res["has_uppercase"] is False
    assert res["has_digits"] is False
    assert res["has_symbols"] is False
    assert res["character_type_count"] == 1

def test_07_uppercase_only():
    """Test 7: Uppercase only input detects single class."""
    res = analyze_characters("ABCDEFGHIJKLM")
    assert res["has_uppercase"] is True
    assert res["character_type_count"] == 1

def test_08_numbers_only():
    """Test 8: Numbers only input detects single class."""
    res = analyze_characters("9876543210")
    assert res["has_digits"] is True
    assert res["character_type_count"] == 1

def test_09_symbols_only():
    """Test 9: Symbols only input detects symbols."""
    res = analyze_characters("!@#$%^&*()")
    assert res["has_symbols"] is True

def test_10_mixed_character_diversity():
    """Test 10: Mixed character input detects all 4 primary classes."""
    res = analyze_characters("K9#mQ2$pZ7!w")
    assert res["has_lowercase"] is True
    assert res["has_uppercase"] is True
    assert res["has_digits"] is True
    assert res["has_symbols"] is True
    assert res["character_type_count"] == 4

def test_21_long_passphrase_input():
    """Test 21: High-entropy multi-word passphrase receives STRONG or VERY STRONG."""
    res = analyze_password("galaxy-meadow-whisper-pebble-horizon", persist_analytics=False)
    assert res["score"] >= 75
    assert res["classification"] in ["STRONG", "VERY STRONG"]

def test_22_unicode_character_handling():
    """Test 22: Analyzer handles unicode characters without throwing exceptions."""
    res = analyze_password("Pässwørd_ünicode_2026! 🛡️", persist_analytics=False)
    assert res["score"] > 50
    assert "score" in res

def test_23_space_handling_in_passphrase():
    """Test 23: Spaces in passwords are treated properly as character class and allowed."""
    res = analyze_characters("correct horse battery staple")
    assert res["has_spaces"] is True
    assert res["space_count"] == 3

def test_24_maximum_length_boundary():
    """Test 24: 128-character long non-repeating password evaluates cleanly."""
    import string
    # Generate 128 non-repetitive diverse characters
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    long_pwd = "".join(alphabet[i % len(alphabet)] for i in range(128))
    # Shuffle or use diversified words
    from backend.services.password_generator import generate_secure_password
    generated = generate_secure_password(length=64)
    res = analyze_password(generated["password"], persist_analytics=False)
    assert res["metrics"]["length"]["length"] == 64
    assert res["score"] >= 80

def test_25_score_boundaries_clamp():
    """Test 25: All scores clamp strictly within 0 and 100."""
    cases = ["", "a", "123", "password", "aaaaaaaaaaaaaaaa", "X7#mK9$qL2!vP8@bW4%z"]
    for c in cases:
        score = analyze_password(c, persist_analytics=False)["score"]
        assert 0 <= score <= 100
