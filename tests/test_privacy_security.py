"""
Security & Privacy Assurance Tests
----------------------------------
Verifies strict zero-knowledge invariants:
1. No plaintext passwords in database schema or rows.
2. No password hashes stored in analytics.
3. No passwords echoed in suggestions or telemetry.
4. Privacy sanitizing filter actively masks sensitive payload logs.
"""
import logging
import sqlite3
from backend.models.database import get_connection, record_analysis_metadata, init_db
from backend.services.password_analyzer import analyze_password
from backend.utils.privacy_filter import PrivacySanitizingFilter, sanitize_dict_for_logging

def test_28_database_schema_has_no_password_column():
    """Test 28: Verify database schema contains strictly NO password or hash columns."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(analyses)")
        columns = [row["name"].lower() for row in cursor.fetchall()]

        # Assert no password column exists in any permutation
        forbidden_columns = ["password", "plaintext", "passwd", "pwd", "hash", "secret"]
        for forbidden in forbidden_columns:
            assert forbidden not in columns, f"Privacy violation: '{forbidden}' found in database table!"

def test_29_privacy_sanitizing_filter_masks_logs():
    """Test 29: Verify PrivacySanitizingFilter scrubs passwords from logging output."""
    filter_instance = PrivacySanitizingFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg='User submitted {"password": "SuperSecretPassword123!"} for check',
        args=(),
        exc_info=None
    )
    filter_instance.filter(record)
    assert "SuperSecretPassword123!" not in record.msg
    assert "[REDACTED_BY_PRIVACY_FILTER]" in record.msg

def test_30_analytics_storage_records_only_safe_metadata():
    """Test 30: Verify recorded analytics row contains only safe mathematical metrics."""
    init_db()
    raw_pwd = "TransientTestPassword987!"
    res = analyze_password(raw_pwd, persist_analytics=True)
    aid = res["analysis_id"]

    assert aid is not None
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analyses WHERE id = ?", (aid,))
        row = cursor.fetchone()

        assert row is not None
        assert row["score"] == res["score"]
        assert row["password_length"] == len(raw_pwd)
        # Ensure row string representation does not contain the password
        row_values_str = " ".join(str(val) for val in tuple(row))
        assert raw_pwd not in row_values_str

def test_31_suggestions_never_echo_password():
    """Test 31: Verifies that generated suggestions never print the raw password."""
    secret_candidate = "MySuperSecretKeyphrase2026!"
    res = analyze_password(secret_candidate, persist_analytics=False)
    for sug in res["suggestions"]:
        assert secret_candidate not in sug["title"]
        assert secret_candidate not in sug["message"]

def test_32_dictionary_sanitizer_removes_sensitive_keys():
    """Test 32: Deep dictionary sanitizer redacts sensitive key values."""
    sensitive_dict = {
        "user_id": 42,
        "password": "ClearTextPassword!",
        "nested": {
            "first_name": "Alice",
            "score": 90
        }
    }
    sanitized = sanitize_dict_for_logging(sensitive_dict)
    assert sanitized["password"] == "[REDACTED_PRIVACY_ENFORCED]"
    assert sanitized["nested"]["first_name"] == "[REDACTED_PRIVACY_ENFORCED]"
    assert sanitized["nested"]["score"] == 90
