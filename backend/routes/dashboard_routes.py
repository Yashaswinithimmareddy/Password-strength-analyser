"""
Dashboard Routes
----------------
Provides anonymous, aggregate telemetry and statistical metrics for security visualization.
Zero-Knowledge Rule: Only non-invertible statistical counts and frequencies are exposed.
"""
from flask import Blueprint, jsonify
from ..models.database import get_dashboard_statistics

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

@dashboard_bp.route("/stats", methods=["GET"])
def stats_endpoint():
    """
    GET /api/dashboard/stats
    Returns aggregated dashboard metrics including score distributions,
    length distributions, and common pattern frequencies.
    """
    stats = get_dashboard_statistics()
    return jsonify(stats), 200

@dashboard_bp.route("/weaknesses", methods=["GET"])
def weaknesses_endpoint():
    """
    GET /api/dashboard/weaknesses
    Returns frequency breakdown of detected weakness types for charting.
    """
    stats = get_dashboard_statistics()
    return jsonify({
        "weakness_frequency": stats.get("weakness_frequency", {}),
        "total_analyses": stats.get("total_analyses", 0)
    }), 200
