"""
Analysis Routes
---------------
Defines REST API endpoints for transient password evaluation and policy checks.
Zero-Knowledge Rule: Requests are processed purely in volatile memory. Request bodies are not logged.
"""
from flask import Blueprint, request, jsonify
from ..services.password_analyzer import analyze_password
from ..services.policy_checker import evaluate_password_policy

analysis_bp = Blueprint("analysis", __name__, url_prefix="/api")

@analysis_bp.route("/analyze", methods=["POST"])
def analyze_endpoint():
    """
    POST /api/analyze
    Transiently evaluates candidate password strength and returns structured defensive report.
    """
    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    context = payload.get("context", {})
    custom_policy = payload.get("custom_policy", None)
    persist = payload.get("persist_analytics", True)

    # Enforce safe length limit (128 characters) to defend against memory exhaustion attacks
    if len(password) > 256:
        return jsonify({
            "error": "Password length exceeds safety limit of 256 characters for live analysis."
        }), 400

    result = analyze_password(
        password=password,
        context=context,
        custom_policy=custom_policy,
        persist_analytics=persist
    )

    return jsonify(result), 200

@analysis_bp.route("/check-policy", methods=["POST"])
def check_policy_endpoint():
    """
    POST /api/check-policy
    Validates a password against configurable administrative rules.
    """
    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    custom_policy = payload.get("custom_policy", {})

    policy_result = evaluate_password_policy(
        password=password,
        custom_policy=custom_policy
    )

    return jsonify(policy_result), 200
