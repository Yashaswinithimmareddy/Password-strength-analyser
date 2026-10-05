"""
Security Suggestion Engine Service
----------------------------------
Generates actionable, specific, prioritized defensive guidance.
Adheres strictly to the privacy rule: NEVER echo or reveal user passwords in suggestions.
"""

def generate_security_suggestions(
    length_metrics: dict,
    char_metrics: dict,
    common_metrics: dict,
    pattern_metrics: dict,
    context_metrics: dict,
    score: int
) -> list:
    """
    Produce specific, actionable guidance to improve password resilience and account hygiene.

    Returns:
        list of dicts: Prioritized suggestions with action titles, rationale, and category.
    """
    suggestions = []

    # 1. Critical: Common password match
    if common_metrics.get("is_common"):
        suggestions.append({
            "priority": "CRITICAL",
            "category": "DICTIONARY_DEFENSE",
            "title": "Replace Known Common / Default Password",
            "message": (
                "Your password matches or closely derives from a commonly used credential. "
                "Attackers test wordlists with millions of common passwords within milliseconds. "
                "Choose an entirely unpredictable phrase."
            )
        })

    # 2. Critical: Personal Context Overlap
    if context_metrics.get("has_context_overlap"):
        suggestions.append({
            "priority": "CRITICAL",
            "category": "OSINT_RESISTANCE",
            "title": "Remove Personal and Demographic Identifiers",
            "message": (
                "Do not include names, birth years, family details, or company names. "
                "Cybercriminals use open-source intelligence (OSINT) from social media "
                "to generate targeted, custom dictionary attacks."
            )
        })

    # 3. Length Recommendation
    length = length_metrics.get("length", 0)
    if length < 8:
        suggestions.append({
            "priority": "HIGH",
            "category": "LENGTH",
            "title": "Substantially Increase Length",
            "message": (
                "Your password is under 8 characters and can be cracked almost instantaneously. "
                "Modern security guidelines recommend at least 12 to 16 characters."
            )
        })
    elif length < 12:
        suggestions.append({
            "priority": "MEDIUM",
            "category": "LENGTH",
            "title": "Expand Towards 14-16 Characters",
            "message": (
                "Expanding beyond 12 characters exponentially inflates the theoretical search space, "
                "rendering offline brute-force attacks infeasible."
            )
        })

    # 4. Sequential Patterns
    seq_analysis = pattern_metrics.get("sequence_analysis", {})
    if seq_analysis.get("has_sequences"):
        suggestions.append({
            "priority": "HIGH",
            "category": "PATTERN_ELIMINATION",
            "title": "Remove Predictable Sequences",
            "message": (
                "Predictable ascending or descending sequences (e.g. 1234, abcd) are prioritized "
                "by mask cracking modes. Replace sequential runs with random or uncorrelated words."
            )
        })

    # 5. Keyboard Walks
    kbd_analysis = pattern_metrics.get("keyboard_analysis", {})
    if kbd_analysis.get("has_keyboard_patterns"):
        suggestions.append({
            "priority": "HIGH",
            "category": "PATTERN_ELIMINATION",
            "title": "Eliminate Keyboard Walks",
            "message": (
                "Physical keyboard walks (e.g. 'qwerty', 'asdf', numpad rows) are indexed "
                "in standard cracking rule engines. Avoid spatial layout shortcuts."
            )
        })

    # 6. Repetition
    rep_analysis = pattern_metrics.get("repetition_analysis", {})
    if rep_analysis.get("has_repetition"):
        suggestions.append({
            "priority": "HIGH",
            "category": "ENTROPY_LOSS",
            "title": "Eliminate Repeated Characters or Substrings",
            "message": (
                "Repeating identical characters or repeating word fragments gives an illusion of length "
                "without adding mathematical entropy. Use diverse, unrelated terms."
            )
        })

    # 7. Predictable Corporate Structure
    struct_analysis = pattern_metrics.get("structure_analysis", {})
    if struct_analysis.get("has_predictable_structure"):
        suggestions.append({
            "priority": "MEDIUM",
            "category": "STRUCTURAL_VARIETY",
            "title": "Break the 'Word + Number + Symbol' Habit",
            "message": (
                "Predictable patterns (e.g., Capitalizing the first letter and adding a year or '!' at the end) "
                "are the exact permutations tried first by hybrid dictionary attacks."
            )
        })

    # 8. Character Diversity (only if length is okay but diversity is mono-type)
    char_types = char_metrics.get("character_type_count", 0)
    if char_types <= 1 and length >= 8:
        suggestions.append({
            "priority": "MEDIUM",
            "category": "DIVERSITY",
            "title": "Introduce Broader Character Types",
            "message": (
                "Using only one character class restricts the character pool size N. "
                "Incorporate a mix of uppercase, lowercase, numbers, or symbols."
            )
        })

    # 9. Passphrase Guidance (Best practice for human recall)
    if score < 80:
        suggestions.append({
            "priority": "LOW",
            "category": "PASSPHRASE_GUIDANCE",
            "title": "Consider a Multi-Word Passphrase",
            "message": (
                "Consider using a 4 to 5 random word passphrase (e.g., 'correct-horse-battery-staple' style). "
                "Passphrases provide high mathematical entropy while remaining easy for humans to type and remember."
            )
        })

    # 10. Universal Hygiene Recommendations (defense-in-depth)
    suggestions.append({
        "priority": "BEST_PRACTICE",
        "category": "CREDENTIAL_HYGIENE",
        "title": "Never Reuse Passwords Across Accounts",
        "message": (
            "Password reuse enables credential stuffing attacks: a single breach on a third-party website "
            "can compromise your banking, email, or enterprise accounts."
        )
    })

    suggestions.append({
        "priority": "BEST_PRACTICE",
        "category": "TOOLING",
        "title": "Use a Dedicated Password Manager",
        "message": (
            "Adopt an audited password manager (such as Bitwarden, 1Password, or KeePass) "
            "to automatically generate, encrypt, and autofill 20+ character random credentials."
        )
    })

    suggestions.append({
        "priority": "BEST_PRACTICE",
        "category": "MFA",
        "title": "Enable Multi-Factor Authentication (MFA)",
        "message": (
            "Even the strongest password can be phished or intercepted. "
            "Enable FIDO2/WebAuthn hardware keys or authenticator apps (TOTP) to protect authentication."
        )
    })

    return suggestions
