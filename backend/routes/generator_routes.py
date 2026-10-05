"""
Generator and Educational Routes
--------------------------------
Provides secure random credential generation (via secrets CSPRNG)
and interactive password hashing demonstrations.
"""
from flask import Blueprint, request, jsonify
from ..services.password_generator import generate_secure_password, generate_passphrase
from ..services.hashing_demo import run_hashing_demonstration

generator_bp = Blueprint("generator", __name__, url_prefix="/api")

@generator_bp.route("/generate-password", methods=["POST"])
def generate_password_endpoint():
    """
    POST /api/generate-password
    Generates a cryptographically random high-entropy password.
    """
    payload = request.get_json(silent=True) or {}
    length = int(payload.get("length", 20))
    include_upper = payload.get("include_uppercase", True)
    include_lower = payload.get("include_lowercase", True)
    include_digits = payload.get("include_digits", True)
    include_symbols = payload.get("include_symbols", True)
    avoid_ambiguous = payload.get("avoid_ambiguous", True)

    generated = generate_secure_password(
        length=length,
        include_uppercase=include_upper,
        include_lowercase=include_lower,
        include_digits=include_digits,
        include_symbols=include_symbols,
        avoid_ambiguous=avoid_ambiguous
    )
    return jsonify(generated), 200

@generator_bp.route("/generate-passphrase", methods=["POST"])
def generate_passphrase_endpoint():
    """
    POST /api/generate-passphrase
    Generates a high-entropy multi-word passphrase.
    """
    payload = request.get_json(silent=True) or {}
    word_count = int(payload.get("word_count", 5))
    delimiter = str(payload.get("delimiter", "-"))

    passphrase_data = generate_passphrase(word_count=word_count, delimiter=delimiter)
    return jsonify(passphrase_data), 200

@generator_bp.route("/hashing-demo", methods=["GET"])
def hashing_demo_endpoint():
    """
    GET /api/hashing-demo
    Runs educational comparison of fast vs salted slow key-stretching functions using synthetic passwords.
    """
    demo_input = request.args.get("sample", "CorrectHorseBatteryStaple2026!")
    # Restrict sample length for safety
    if len(demo_input) > 64:
        demo_input = demo_input[:64]

    result = run_hashing_demonstration(demo_password=demo_input)
    return jsonify(result), 200
