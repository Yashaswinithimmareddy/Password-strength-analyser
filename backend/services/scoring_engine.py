"""
Password Strength Scoring Engine
--------------------------------
Computes a calibrated 0-100 score based on positive structural contributions
and defensive pattern deductions.

Positive Contributions (Max 100):
  - Length Contribution: up to +35
  - Character Diversity: up to +15
  - Unique-Character Ratio: up to +10
  - Pattern Resistance (absence of walks/repeats): up to +20
  - Non-Common Password Baseline: up to +10
  - Unpredictability / Effective Entropy: up to +10

Deductions:
  - Common Password: up to -50
  - Sequential Patterns: -15
  - Keyboard Walks: -15
  - Repetitive Characters/Substrings: up to -25
  - Personal Context Overlap: -25
  - Predictable Composition: up to -15

Bands:
  - 0-20:   VERY WEAK
  - 21-40:  WEAK
  - 41-60:  MODERATE
  - 61-80:  STRONG
  - 81-100: VERY STRONG
"""

def calculate_strength_score(
    length_metrics: dict,
    char_metrics: dict,
    common_metrics: dict,
    pattern_metrics: dict,
    context_metrics: dict,
    entropy_metrics: dict
) -> dict:
    """
    Synthesize all analytical dimensions into a unified score (0-100) and classification.

    Returns:
        dict: Final score, classification, breakdown of additions and deductions.
    """
    length = length_metrics.get("length", 0)
    if length == 0:
        return {
            "score": 0,
            "classification": "VERY WEAK",
            "score_band": "0-20",
            "breakdown": {
                "base_contributions": {},
                "penalties": {}
            },
            "summary": "Password is empty."
        }

    # 1. Base Additions
    length_pts = length_metrics.get("score_contribution", 0) # max 35
    diversity_pts = char_metrics.get("diversity_score", 0)   # max 15
    uniqueness_pts = char_metrics.get("uniqueness_score", 0) # max 10

    # Pattern resistance reward (if clean of walks/repeats)
    has_patterns = pattern_metrics.get("has_any_pattern", False)
    pattern_resistance_pts = 0 if has_patterns else 20

    # Non-common reward
    is_common = common_metrics.get("is_common", False)
    non_common_pts = 0 if is_common else 10

    # Effective entropy reward
    adj_bits = entropy_metrics.get("adjusted_bits", 0.0)
    if adj_bits >= 75:
        entropy_pts = 10
    elif adj_bits >= 55:
        entropy_pts = 7
    elif adj_bits >= 40:
        entropy_pts = 4
    else:
        entropy_pts = 1

    total_positive = length_pts + diversity_pts + uniqueness_pts + pattern_resistance_pts + non_common_pts + entropy_pts

    # 2. Deductions
    common_penalty = common_metrics.get("penalty", 0)       # up to -50
    pattern_penalty = pattern_metrics.get("total_penalty", 0) # up to -40
    context_penalty = context_metrics.get("penalty", 0)       # up to -25

    total_deductions = common_penalty + pattern_penalty + context_penalty

    # Raw score calculation
    raw_score = total_positive + total_deductions

    # Short password hard caps:
    # A password under 8 characters can never be classified above WEAK
    if length < 8:
        raw_score = min(raw_score, 20)
    elif length < 12 and raw_score > 60:
        raw_score = 60 # capped at MODERATE if under 12 characters

    # Clamp strictly between 0 and 100
    final_score = int(round(max(0, min(100, raw_score))))

    # Determine classification band
    if final_score <= 20:
        classification = "VERY WEAK"
        band = "0-20"
    elif final_score <= 40:
        classification = "WEAK"
        band = "21-40"
    elif final_score <= 60:
        classification = "MODERATE"
        band = "41-60"
    elif final_score <= 80:
        classification = "STRONG"
        band = "61-80"
    else:
        classification = "VERY STRONG"
        band = "81-100"

    return {
        "score": final_score,
        "classification": classification,
        "score_band": band,
        "breakdown": {
            "positive_contributions": {
                "length_points": length_pts,
                "character_diversity_points": diversity_pts,
                "uniqueness_ratio_points": uniqueness_pts,
                "pattern_resistance_points": pattern_resistance_pts,
                "non_common_baseline_points": non_common_pts,
                "entropy_unpredictability_points": entropy_pts,
                "total_positive": round(total_positive, 1)
            },
            "penalties": {
                "common_password_penalty": common_penalty,
                "pattern_deductions": pattern_penalty,
                "personal_context_penalty": context_penalty,
                "total_deductions": total_deductions
            }
        },
        "summary": (
            f"Evaluated as {classification} ({final_score}/100). "
            "Scoring combines NIST-aligned length expectations with defensive pattern suppression."
        )
    }
