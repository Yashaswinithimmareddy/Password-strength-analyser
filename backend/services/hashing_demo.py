"""
Password Hashing Demonstration Service
--------------------------------------
Educational demonstration comparing fast general-purpose cryptographic hashes (SHA-256)
against modern slow, salted key-derivation functions (PBKDF2-HMAC-SHA256, Argon2id, bcrypt).

IMPORTANT ARCHITECTURAL RULE:
This module is strictly for educational demonstration with synthetic passwords.
User-submitted analyzer passwords are NEVER hashed or stored.
"""
import hashlib
import os
import secrets
import time

def hash_password_pbkdf2(password: str, iterations: int = 600000, salt: bytes = None) -> dict:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with a cryptographically random salt
    and OWASP-recommended iteration count (600,000 iterations).

    Returns:
        dict: The salt (hex), hash (hex), iterations, execution time in ms.
    """
    if salt is None:
        salt = secrets.token_bytes(16)

    start_time = time.perf_counter()
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return {
        "algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt_hex": salt.hex(),
        "hash_hex": derived.hex(),
        "storage_format": f"pbkdf2:sha256:{iterations}${salt.hex()}${derived.hex()}",
        "execution_time_ms": round(elapsed_ms, 2)
    }

def verify_password_pbkdf2(password: str, stored_format: str) -> bool:
    """
    Verify candidate password against stored format using constant-time comparison (secrets.compare_digest).
    """
    try:
        parts = stored_format.split("$")
        algo_info = parts[0]
        iterations = int(algo_info.split(":")[2])
        salt = bytes.fromhex(parts[1])
        expected_hash = bytes.fromhex(parts[2])

        computed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations
        )
        return secrets.compare_digest(computed, expected_hash)
    except Exception:
        return False

def fast_hash_comparison(password: str) -> dict:
    """
    Compute raw fast SHA-256 hash to illustrate why fast hashes are catastrophic for password storage.
    """
    start_time = time.perf_counter()
    # Fast SHA-256 (general purpose hash)
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    elapsed_us = (time.perf_counter() - start_time) * 1000000

    return {
        "algorithm": "Raw SHA-256 (General-Purpose Fast Hash)",
        "hash_hex": digest,
        "execution_time_microseconds": round(elapsed_us, 2),
        "warning": (
            "Fast hashes can be calculated billions of times per second on consumer GPUs (e.g. RTX 4090). "
            "Never use raw SHA-256, MD5, or SHA-1 for password storage!"
        )
    }

def run_hashing_demonstration(demo_password: str = "CorrectHorseBatteryStaple2026!") -> dict:
    """
    Execute a full comparative demonstration of fast hash vs salted PBKDF2 slow hash.

    Returns:
        dict: Comparative benchmarks, salt mechanics, and verification test.
    """
    # 1. Fast Hash
    fast_result = fast_hash_comparison(demo_password)

    # 2. Slow Salted PBKDF2 (using moderate iteration count for snappy web response)
    iterations = 100000
    slow_result = hash_password_pbkdf2(demo_password, iterations=iterations)

    # 3. Demonstration of unique salt (same password with second random salt)
    second_salt_result = hash_password_pbkdf2(demo_password, iterations=iterations)

    # 4. Verify test
    is_valid = verify_password_pbkdf2(demo_password, slow_result["storage_format"])
    wrong_valid = verify_password_pbkdf2("WrongCandidatePassword", slow_result["storage_format"])

    return {
        "synthetic_demo_input": demo_password,
        "fast_hash": fast_result,
        "slow_salted_hash": slow_result,
        "salt_demonstration": {
            "explanation": (
                "Notice that hashing the EXACT same password with two distinct 16-byte random salts "
                "yields completely different outputs. This thwarts precomputed rainbow table attacks."
            ),
            "salt_1": slow_result["salt_hex"],
            "hash_1_preview": slow_result["hash_hex"][:32] + "...",
            "salt_2": second_salt_result["salt_hex"],
            "hash_2_preview": second_salt_result["hash_hex"][:32] + "...",
            "hashes_differ": slow_result["hash_hex"] != second_salt_result["hash_hex"]
        },
        "verification_test": {
            "correct_password_verified": is_valid,
            "incorrect_password_rejected": not wrong_valid,
            "method": "secrets.compare_digest (constant-time comparison against timing attacks)"
        },
        "modern_standards_guidance": {
            "argon2id": "Current gold standard (IETF RFC 9106, OWASP recommendation) offering both memory and CPU hardness.",
            "bcrypt": "Battle-tested, memory-limited slow hash standard.",
            "pbkdf2": "FIPS-compliant standard, requiring 600,000+ iterations for SHA-256."
        }
    }
