"""
Master Password Analysis Engine
-------------------------------
Orchestrates length analysis, character diversity, common password detection,
pattern recognition, context checking, entropy calculation, calibrated scoring,
and security recommendations.

Zero-Knowledge Privacy Guarantee:
The analyzed password is held strictly in volatile execution frames during the request,
and is discarded immediately after analysis. It is never logged, saved, or transmitted.
"""
from .length_analyzer import analyze_length
from .character_analyzer import analyze_characters
from .common_password_checker import is_common_password
from .pattern_detector import detect_all_patterns
from .context_checker import check_personal_context
from .entropy_estimator import estimate_entropy
from .scoring_engine import calculate_strength_score
from .suggestion_engine import generate_security_suggestions
from .policy_checker import evaluate_password_policy
from ..models.database import record_analysis_metadata

def analyze_password(
    password: str,
    context: dict = None,
    custom_policy: dict = None,
    persist_analytics: bool = True
) -> dict:
    """
    Perform a complete multi-dimensional defensive evaluation of a candidate password.

    Args:
        password (str): Candidate password string (processed strictly in memory).
        context (dict, optional): Voluntary user context (first_name, birth_year, organization).
        custom_policy (dict, optional): Custom enterprise policy rules.
        persist_analytics (bool): Whether to record safe anonymized metrics into SQLite.

    Returns:
        dict: Complete structured evaluation conforming to cybersecurity specifications.
    """
    if password is None:
        password = ""

    # 1. Length Analysis
    len_res = analyze_length(password)

    # 2. Character Diversity Analysis
    char_res = analyze_characters(password)

    # 3. Common / Dictionary Password Check
    common_res = is_common_password(password)

    # 4. Pattern Recognition (Sequences, Keyboard Walks, Repetitions, Formulas)
    pattern_res = detect_all_patterns(password)

    # 5. Personal Demographic Context Check (Zero storage)
    context_res = check_personal_context(password, context)

    # 6. Theoretical & Pattern-Adjusted Information Entropy
    entropy_res = estimate_entropy(
        password,
        patterns_detected=pattern_res,
        is_common=common_res["is_common"]
    )

    # 7. Unified Calibrated Scoring (0 to 100)
    score_res = calculate_strength_score(
        length_metrics=len_res,
        char_metrics=char_res,
        common_metrics=common_res,
        pattern_metrics=pattern_res,
        context_metrics=context_res,
        entropy_metrics=entropy_res
    )

    final_score = score_res["score"]
    classification = score_res["classification"]

    # 8. Compile consolidated findings list
    consolidated_findings = []

    # Common password finding
    if common_res["is_common"]:
        consolidated_findings.append({
            "category": "COMMON_PASSWORD",
            "severity": common_res.get("severity", "CRITICAL"),
            "description": common_res["description"]
        })

    # Length finding
    if len_res["band"] in ["EMPTY", "VERY_SHORT"]:
        consolidated_findings.append({
            "category": "LENGTH",
            "severity": "CRITICAL",
            "description": len_res["description"]
        })
    elif len_res["band"] == "SHORT":
        consolidated_findings.append({
            "category": "LENGTH",
            "severity": "WARNING",
            "description": len_res["description"]
        })

    # Pattern findings
    for p_finding in pattern_res["findings"]:
        consolidated_findings.append(p_finding)

    # Context findings
    if context_res["has_context_overlap"]:
        consolidated_findings.append({
            "category": "PERSONAL_CONTEXT",
            "severity": "CRITICAL",
            "description": context_res["description"]
        })

    # 9. Defensive Security Recommendations
    suggestions = generate_security_suggestions(
        length_metrics=len_res,
        char_metrics=char_res,
        common_metrics=common_res,
        pattern_metrics=pattern_res,
        context_metrics=context_res,
        score=final_score
    )

    # 10. Enterprise Policy Evaluation (Pass / Fail distinct from score)
    policy_res = evaluate_password_policy(
        password=password,
        custom_policy=custom_policy,
        common_analysis=common_res,
        pattern_analysis=pattern_res,
        context_analysis=context_res
    )

    # 11. Optionally persist safe aggregate telemetry (NO PASSWORDS)
    analysis_id = None
    if persist_analytics and len(password) > 0:
        try:
            analysis_id = record_analysis_metadata(
                score=final_score,
                classification=classification,
                password_length=len_res["length"],
                unique_character_ratio=char_res["unique_character_ratio"],
                theoretical_entropy=entropy_res["theoretical_bits"],
                adjusted_entropy=entropy_res["adjusted_bits"],
                findings=consolidated_findings
            )
        except Exception:
            # Failure in telemetry recording must never impede analysis result
            pass

    return {
        "analysis_id": analysis_id,
        "score": final_score,
        "classification": classification,
        "score_band": score_res["score_band"],
        "findings": consolidated_findings,
        "suggestions": suggestions,
        "metrics": {
            "length": len_res,
            "characters": char_res,
            "common_check": common_res,
            "patterns": pattern_res,
            "context": context_res,
            "entropy": entropy_res,
            "policy": policy_res,
            "scoring_breakdown": score_res["breakdown"]
        },
        "privacy_audit": {
            "password_stored": False,
            "password_logged": False,
            "external_transmission": False,
            "architecture": "Defensive In-Memory Transient Processing"
        }
    }
