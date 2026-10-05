"""
Enterprise Password Policy Checker Service
------------------------------------------
Evaluates whether a candidate password complies with configurable enterprise policies
(aligned with NIST SP 800-63B Digital Identity Guidelines).

KEY EDUCATIONAL DISTINCTION:
Policy Compliance != True Password Strength.
A password can pass an outdated composition policy (e.g. 'Password123!') while being trivial to crack.
Conversely, a 20-character lowercase passphrase ('galaxy meadow whisper pebble') may fail legacy policies
yet boast astronomical entropy and brute-force resistance.
"""

DEFAULT_POLICY = {
    "min_length": 12,
    "max_length": 128,
    "require_lowercase": True,
    "require_uppercase": False,  # NIST SP 800-63B recommends against mandatory arbitrary composition rules
    "require_digits": False,
    "require_symbols": False,
    "disallow_common_passwords": True,
    "allow_spaces": True,
    "disallow_repetition": True,
}

def evaluate_password_policy(
    password: str,
    custom_policy: dict = None,
    common_analysis: dict = None,
    pattern_analysis: dict = None,
    context_analysis: dict = None
) -> dict:
    """
    Evaluate candidate password against enterprise policy rules.

    Returns:
        dict: Overall status (PASS/FAIL), check item breakdown, and educational comparison.
    """
    if password is None:
        password = ""

    policy = dict(DEFAULT_POLICY)
    if custom_policy:
        policy.update(custom_policy)

    checks = []
    overall_pass = True

    # 1. Minimum Length Check
    min_len = policy.get("min_length", 12)
    len_pass = len(password) >= min_len
    if not len_pass:
        overall_pass = False
    checks.append({
        "rule": f"Minimum Length ({min_len} characters)",
        "passed": len_pass,
        "detail": f"Actual length: {len(password)} characters."
    })

    # 2. Maximum Length Check (Defense against DoS through excessive hashing payloads)
    max_len = policy.get("max_length", 128)
    max_pass = len(password) <= max_len
    if not max_pass:
        overall_pass = False
    checks.append({
        "rule": f"Maximum Length ({max_len} characters)",
        "passed": max_pass,
        "detail": "Prevents Long-Password Denial of Service (DoS) in cryptographic hashing algorithms."
    })

    # 3. Disallow Known Common Passwords (NIST requirement)
    if policy.get("disallow_common_passwords", True):
        is_common = common_analysis.get("is_common", False) if common_analysis else False
        common_pass = not is_common
        if not common_pass:
            overall_pass = False
        checks.append({
            "rule": "Blacklist Check (No Known Common/Breached Passwords)",
            "passed": common_pass,
            "detail": "Passes" if common_pass else f"Rejected: matches common entry '{common_analysis.get('matched_word')}'."
        })

    # 4. Spaces Permitted Check (Passphrase enablement)
    has_spaces = " " in password
    if policy.get("allow_spaces", True):
        checks.append({
            "rule": "Allow Spaces (Passphrase Friendly)",
            "passed": True,
            "detail": "Spaces are permitted to support multi-word natural passphrases."
        })

    # 5. Repetition Check
    if policy.get("disallow_repetition", True):
        has_heavy_rep = False
        if pattern_analysis:
            rep = pattern_analysis.get("repetition_analysis", {})
            has_heavy_rep = rep.get("has_repetition", False) and rep.get("penalty", 0) <= -20
        rep_pass = not has_heavy_rep
        if not rep_pass:
            overall_pass = False
        checks.append({
            "rule": "Excessive Repetition Check",
            "passed": rep_pass,
            "detail": "Passes" if rep_pass else "Rejected: contains excessive repeated characters or substrings."
        })

    # 6. Personal context check if provided
    if context_analysis and context_analysis.get("has_context_overlap", False):
        overall_pass = False
        checks.append({
            "rule": "Personal Context Restriction",
            "passed": False,
            "detail": "Rejected: contains user-specific demographic identifiers."
        })

    status_label = "POLICY PASS" if overall_pass else "POLICY FAIL"

    return {
        "status": status_label,
        "passed": overall_pass,
        "policy_rules_evaluated": len(checks),
        "rules_passed_count": sum(1 for c in checks if c["passed"]),
        "checks": checks,
        "educational_distinction": (
            "Compliance with a policy confirms administrative boundary alignment, "
            "whereas strength score reflects actual algorithmic resilience against modern cracking models."
        )
    }
