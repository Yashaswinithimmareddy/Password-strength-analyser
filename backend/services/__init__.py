"""
Backend services package initialization.
Exports all defensive password analysis, pattern detection, entropy, and scoring components.
"""
from .length_analyzer import analyze_length
from .character_analyzer import analyze_characters
from .common_password_checker import is_common_password
from .sequence_detector import detect_sequences
from .keyboard_detector import detect_keyboard_patterns
from .repetition_detector import detect_repetition
from .pattern_detector import detect_all_patterns
from .context_checker import check_personal_context
from .entropy_estimator import estimate_entropy
from .scoring_engine import calculate_strength_score
from .suggestion_engine import generate_security_suggestions
from .policy_checker import evaluate_password_policy
from .password_generator import generate_secure_password, generate_passphrase
from .hashing_demo import run_hashing_demonstration
from .password_analyzer import analyze_password

__all__ = [
    "analyze_length",
    "analyze_characters",
    "is_common_password",
    "detect_sequences",
    "detect_keyboard_patterns",
    "detect_repetition",
    "detect_all_patterns",
    "check_personal_context",
    "estimate_entropy",
    "calculate_strength_score",
    "generate_security_suggestions",
    "evaluate_password_policy",
    "generate_secure_password",
    "generate_passphrase",
    "run_hashing_demonstration",
    "analyze_password",
]
