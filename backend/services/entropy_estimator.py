"""
Entropy Estimator Service
-------------------------
Calculates theoretical Shannon information entropy and pattern-discounted effective entropy.

Theoretical Entropy formula:
    Entropy (bits) = L * log2(N)
where:
    L = password length
    N = character pool size based on character classes present

CRITICAL DEFENSIVE LIMITATION:
Theoretical entropy assumes characters were sampled uniformly and independently at random.
Human users follow predictable grammatical, spatial, and numeric conventions.
Therefore, a password like 'Password123!' may show ~71 bits of theoretical entropy,
even though cracking tools exhaust it in seconds. We provide an Adjusted Entropy score
that discounts for detected non-random patterns.
"""
import math
import string

def _format_time_span(seconds: float) -> str:
    """Format seconds into human-readable educational time span."""
    if seconds <= 0.001:
        return "Instant (< 1 millisecond)"
    elif seconds < 1:
        return f"{round(seconds * 1000, 1)} milliseconds"
    elif seconds < 60:
        return f"{round(seconds, 1)} seconds"
    elif seconds < 3600:
        return f"{round(seconds / 60, 1)} minutes"
    elif seconds < 86400:
        return f"{round(seconds / 3600, 1)} hours"
    elif seconds < 31536000:
        return f"{round(seconds / 86400, 1)} days"
    elif seconds < 31536000 * 100:
        return f"{round(seconds / 31536000, 1)} years"
    elif seconds < 31536000 * 1000000:
        return f"{round(seconds / (31536000 * 1000), 1)} thousand years"
    else:
        return "Centuries / Practically Infeasible"

def estimate_entropy(password: str, patterns_detected: dict = None, is_common: bool = False) -> dict:
    """
    Calculate theoretical Shannon entropy and realistic pattern-adjusted entropy.

    Returns:
        dict: Theoretical bits, adjusted bits, character pool size N, and educational crack resistance estimates.
    """
    if not password:
        return {
            "theoretical_bits": 0.0,
            "adjusted_bits": 0.0,
            "pool_size": 0,
            "pool_breakdown": "None",
            "crack_estimates": {
                "online_throttled_100_per_sec": "Instant",
                "hardened_slow_hash_10k_per_sec": "Instant",
                "fast_gpu_cluster_100b_per_sec": "Instant"
            },
            "educational_note": "Empty password provides zero entropy."
        }

    length = len(password)
    pool_size = 0
    pool_parts = []

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_space = any(c.isspace() for c in password)
    has_symbol = any(c in string.punctuation or (not c.isalnum() and not c.isspace()) for c in password)

    if has_lower:
        pool_size += 26
        pool_parts.append("Lowercase (26)")
    if has_upper:
        pool_size += 26
        pool_parts.append("Uppercase (26)")
    if has_digit:
        pool_size += 10
        pool_parts.append("Digits (10)")
    if has_space:
        pool_size += 1
        pool_parts.append("Space (1)")
    if has_symbol:
        pool_size += 33
        pool_parts.append("Symbols (33)")

    pool_size = max(pool_size, 1)

    # Theoretical Shannon entropy
    theoretical_bits = round(length * math.log2(pool_size), 2)

    # Adjusted Entropy Calculation (Discounting for human predictability)
    discount = 0.0
    if is_common:
        # Common passwords reduce effective entropy to near zero
        discount += 0.85
    else:
        if patterns_detected:
            if patterns_detected.get("sequence_analysis", {}).get("has_sequences"):
                discount += 0.20
            if patterns_detected.get("keyboard_analysis", {}).get("has_keyboard_patterns"):
                discount += 0.25
            if patterns_detected.get("repetition_analysis", {}).get("has_repetition"):
                discount += 0.35
            if patterns_detected.get("structure_analysis", {}).get("has_predictable_structure"):
                discount += 0.20

    discount = min(0.90, discount)
    adjusted_bits = round(theoretical_bits * (1.0 - discount), 2)

    # Estimated search space combinations = 2^adjusted_bits
    combinations = 2 ** min(adjusted_bits, 128)

    # Scenarios for educational comparison:
    # 1. Online service with rate limiting (100 guesses / second)
    online_sec = combinations / 100.0
    # 2. Hardened slow hash (Argon2id / PBKDF2) on server (10,000 guesses / second)
    slow_hash_sec = combinations / 10000.0
    # 3. High-end offline GPU rig cracking fast/unsalted hash like MD5 (100,000,000,000 guesses / second)
    gpu_cluster_sec = combinations / 100000000000.0

    return {
        "theoretical_bits": theoretical_bits,
        "adjusted_bits": adjusted_bits,
        "pool_size": pool_size,
        "pool_breakdown": " + ".join(pool_parts),
        "discount_applied_percent": round(discount * 100, 1),
        "crack_estimates": {
            "online_throttled_100_per_sec": _format_time_span(online_sec),
            "hardened_slow_hash_10k_per_sec": _format_time_span(slow_hash_sec),
            "fast_gpu_cluster_100b_per_sec": _format_time_span(gpu_cluster_sec)
        },
        "educational_note": (
            f"Theoretical entropy ({theoretical_bits} bits) assumes uniform random distribution. "
            f"Accounting for predictable structure reduces practical resistance to ~{adjusted_bits} bits. "
            "Educational estimate only; real-world security depends on threat model and hashing algorithms."
        )
    }
