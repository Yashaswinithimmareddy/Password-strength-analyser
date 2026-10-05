"""
Unit Tests - Pattern Detection Suite
------------------------------------
Tests sequences, keyboard walks, repetitions, and demographic context detection.
"""
import pytest
from backend.services.sequence_detector import detect_sequences
from backend.services.keyboard_detector import detect_keyboard_patterns
from backend.services.repetition_detector import detect_repetition
from backend.services.context_checker import check_personal_context
from backend.services.pattern_detector import detect_all_patterns

def test_11_sequential_numbers_ascending():
    """Test 11: Detects ascending numeric sequence '123456'."""
    res = detect_sequences("abc123456xyz")
    assert res["has_sequences"] is True
    assert any(s["type"] == "numeric_ascending" for s in res["sequences"])
    assert res["penalty"] < 0

def test_12_reverse_numeric_sequence():
    """Test 12: Detects descending numeric sequence '987654'."""
    res = detect_sequences("Pass987654!")
    assert res["has_sequences"] is True
    assert any(s["type"] == "numeric_descending" for s in res["sequences"])

def test_13_sequential_letters():
    """Test 13: Detects alphabetical sequences ascending 'abcd' and descending 'dcba'."""
    res_asc = detect_sequences("testabcd12")
    assert res_asc["has_sequences"] is True
    assert any(s["type"] == "alpha_ascending" for s in res_asc["sequences"])

    res_desc = detect_sequences("testdcba12")
    assert res_desc["has_sequences"] is True
    assert any(s["type"] == "alpha_descending" for s in res_desc["sequences"])

def test_14_keyboard_walk_qwerty():
    """Test 14: Detects standard QWERTY keyboard sequence 'qwerty' and 'asdf'."""
    res = detect_keyboard_patterns("MyqwertyPass!")
    assert res["has_keyboard_patterns"] is True
    assert "qwerty" in res["patterns"]

def test_15_repeated_characters():
    """Test 15: Detects consecutive repeated characters 'aaaaaa'."""
    res = detect_repetition("aaaaaa123!")
    assert res["has_repetition"] is True
    assert any(c["character"] == "a" and c["count"] >= 6 for c in res["repeated_characters"])
    assert res["penalty"] <= -15

def test_16_repeated_substring():
    """Test 16: Detects repeating chunk pattern 'ababab'."""
    res = detect_repetition("ababab123")
    assert res["has_repetition"] is True
    assert any(s["chunk"] == "ab" for s in res["repeated_substrings"])

def test_17_common_word_plus_number():
    """Test 17: Detects predictable structure 'welcome123'."""
    patterns = detect_all_patterns("welcome123")
    assert patterns["has_any_pattern"] is True
    assert patterns["structure_analysis"]["has_predictable_structure"] is True

def test_18_word_plus_year():
    """Test 18: Detects predictable year pattern 'admin2026'."""
    patterns = detect_all_patterns("admin2026")
    assert patterns["has_any_pattern"] is True
    assert any(p["type"] == "year_pattern" for p in patterns["structure_analysis"]["patterns"])

def test_19_personal_name_overlap():
    """Test 19: Identifies when first name overlaps with candidate password."""
    context = {"first_name": "Rahul", "birth_year": "1995", "organization": "Acme"}
    res = check_personal_context("Rahul@123", context)
    assert res["has_context_overlap"] is True
    assert any(m["field"] == "First Name" for m in res["matched_fields"])
    assert res["penalty"] == -25

def test_20_birth_year_overlap():
    """Test 20: Identifies when birth year is embedded in candidate password."""
    context = {"first_name": "Alice", "birth_year": "1998", "organization": "TechCorp"}
    res = check_personal_context("StrongPassword#1998", context)
    assert res["has_context_overlap"] is True
    assert any(m["field"] == "Birth Year" for m in res["matched_fields"])
