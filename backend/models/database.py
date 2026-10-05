"""
Database Module - Privacy-First Analytics Storage
--------------------------------------------------
Zero-Knowledge Architecture:
This database stores ONLY safe, non-reversible aggregate metrics.
Under NO circumstances is any plaintext password, password hash, reversible token,
or sensitive personal context stored in this schema.

Schema:
  1. analyses:
     - id (INTEGER PRIMARY KEY)
     - analyzed_at (TIMESTAMP)
     - score (INTEGER 0-100)
     - classification (TEXT)
     - password_length (INTEGER)
     - unique_character_ratio (REAL)
     - theoretical_entropy (REAL)
     - adjusted_entropy (REAL)
     - weakness_count (INTEGER)

  2. findings:
     - id (INTEGER PRIMARY KEY)
     - analysis_id (INTEGER FK)
     - finding_type (TEXT)
     - severity (TEXT)
     - description (TEXT)
"""
import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "analyzer_analytics.db"
)

def get_connection():
    """Create and return a SQLite database connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables with zero-knowledge schema."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_connection() as conn:
        cursor = conn.cursor()

        # Table 1: Safe metadata analyses (NO password columns)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                password_length INTEGER NOT NULL,
                unique_character_ratio REAL NOT NULL,
                theoretical_entropy REAL NOT NULL,
                adjusted_entropy REAL NOT NULL,
                weakness_count INTEGER NOT NULL DEFAULT 0
            );
        """)

        # Table 2: Findings categories
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses (id) ON DELETE CASCADE
            );
        """)

        conn.commit()

def record_analysis_metadata(
    score: int,
    classification: str,
    password_length: int,
    unique_character_ratio: float,
    theoretical_entropy: float,
    adjusted_entropy: float,
    findings: list
) -> int:
    """
    Persist ONLY non-invertible aggregate metrics to the analytics database.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analyses (
                score, classification, password_length,
                unique_character_ratio, theoretical_entropy,
                adjusted_entropy, weakness_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            score,
            classification,
            password_length,
            unique_character_ratio,
            theoretical_entropy,
            adjusted_entropy,
            len(findings)
        ))
        analysis_id = cursor.lastrowid

        for finding in findings:
            category = finding.get("category", "GENERAL")
            severity = finding.get("severity", "INFO")
            desc = finding.get("description", "")
            cursor.execute("""
                INSERT INTO findings (analysis_id, finding_type, severity, description)
                VALUES (?, ?, ?, ?)
            """, (analysis_id, category, severity, desc))

        conn.commit()
        return analysis_id

def get_dashboard_statistics() -> dict:
    """
    Compute aggregate statistics for defensive dashboard visualizations.
    Returns NO personal data or passwords.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        # Total analyses
        cursor.execute("SELECT COUNT(*) AS total, AVG(score) AS avg_score FROM analyses")
        row = cursor.fetchone()
        total_analyses = row["total"] if row and row["total"] else 0
        avg_score = round(row["avg_score"], 1) if row and row["avg_score"] is not None else 0.0

        # Strength Classification Distribution
        cursor.execute("""
            SELECT classification, COUNT(*) AS count
            FROM analyses
            GROUP BY classification
        """)
        class_counts = {
            "VERY WEAK": 0,
            "WEAK": 0,
            "MODERATE": 0,
            "STRONG": 0,
            "VERY STRONG": 0
        }
        for r in cursor.fetchall():
            class_counts[r["classification"]] = r["count"]

        # Length distribution buckets
        cursor.execute("""
            SELECT
                SUM(CASE WHEN password_length < 8 THEN 1 ELSE 0 END) AS under_8,
                SUM(CASE WHEN password_length BETWEEN 8 AND 11 THEN 1 ELSE 0 END) AS range_8_11,
                SUM(CASE WHEN password_length BETWEEN 12 AND 15 THEN 1 ELSE 0 END) AS range_12_15,
                SUM(CASE WHEN password_length >= 16 THEN 1 ELSE 0 END) AS range_16_plus
            FROM analyses
        """)
        len_row = cursor.fetchone()
        length_dist = {
            "< 8 (Critically Short)": len_row["under_8"] or 0 if len_row else 0,
            "8 - 11 (Short)": len_row["range_8_11"] or 0 if len_row else 0,
            "12 - 15 (Standard)": len_row["range_12_15"] or 0 if len_row else 0,
            "16+ (Recommended)": len_row["range_16_plus"] or 0 if len_row else 0,
        }

        # Most frequent weakness finding categories
        cursor.execute("""
            SELECT finding_type, COUNT(*) AS count
            FROM findings
            GROUP BY finding_type
            ORDER BY count DESC
            LIMIT 6
        """)
        weakness_dist = {r["finding_type"]: r["count"] for r in cursor.fetchall()}

        # Recent safe telemetry (last 8 scans)
        cursor.execute("""
            SELECT id, score, classification, password_length, theoretical_entropy, analyzed_at
            FROM analyses
            ORDER BY id DESC
            LIMIT 8
        """)
        recent_scans = [
            {
                "id": r["id"],
                "score": r["score"],
                "classification": r["classification"],
                "length": r["password_length"],
                "entropy": r["theoretical_entropy"],
                "timestamp": r["analyzed_at"]
            }
            for r in cursor.fetchall()
        ]

        return {
            "total_analyses": total_analyses,
            "average_score": avg_score,
            "classification_distribution": class_counts,
            "length_distribution": length_dist,
            "weakness_frequency": weakness_dist,
            "recent_scans": recent_scans,
            "privacy_statement": "Database contains zero passwords, hashes, or identifiable credentials."
        }

def seed_demo_analytics_if_empty():
    """
    Populate initial anonymous aggregate data points if database is freshly initialized,
    providing ready-to-use charts for classroom demonstrations and screenshots.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM analyses")
        if cursor.fetchone()["total"] == 0:
            demo_records = [
                (14, "VERY WEAK", 6, 0.66, 15.5, 5.0, [{"category": "DICTIONARY_DEFENSE", "severity": "CRITICAL", "description": "Common password match"}]),
                (35, "WEAK", 10, 0.80, 47.0, 28.0, [{"category": "KEYBOARD_WALK", "severity": "WARNING", "description": "Keyboard walk qwerty"}]),
                (52, "MODERATE", 11, 0.90, 52.0, 39.0, [{"category": "PREDICTABLE_STRUCTURE", "severity": "WARNING", "description": "Word + number"}]),
                (74, "STRONG", 15, 0.93, 78.5, 62.0, []),
                (95, "VERY STRONG", 22, 0.95, 120.0, 108.0, []),
                (18, "VERY WEAK", 7, 0.57, 18.0, 6.0, [{"category": "SEQUENCE", "severity": "WARNING", "description": "1234 sequence"}]),
                (38, "WEAK", 9, 0.77, 42.0, 25.0, [{"category": "REPETITION", "severity": "WARNING", "description": "Repeated characters"}]),
                (78, "STRONG", 16, 0.88, 85.0, 72.0, []),
                (88, "VERY STRONG", 20, 0.95, 110.0, 99.0, []),
            ]
            for score, classification, length, uniq, ent_th, ent_adj, findings in demo_records:
                cursor.execute("""
                    INSERT INTO analyses (
                        score, classification, password_length,
                        unique_character_ratio, theoretical_entropy,
                        adjusted_entropy, weakness_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (score, classification, length, uniq, ent_th, ent_adj, len(findings)))
                aid = cursor.lastrowid
                for f in findings:
                    cursor.execute("""
                        INSERT INTO findings (analysis_id, finding_type, severity, description)
                        VALUES (?, ?, ?, ?)
                    """, (aid, f["category"], f["severity"], f["description"]))
            conn.commit()
