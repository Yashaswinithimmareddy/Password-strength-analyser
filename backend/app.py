"""
Main Application Entry Point
----------------------------
Flask application orchestrating REST API endpoints, defensive security headers,
zero-knowledge privacy filters, and serving the frontend interface.
"""
import os
import sys
import logging
from flask import Flask, send_from_directory, jsonify, make_response

# Add project root to Python module search path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.routes.analysis_routes import analysis_bp
from backend.routes.dashboard_routes import dashboard_bp
from backend.routes.generator_routes import generator_bp
from backend.models.database import init_db, seed_demo_analytics_if_empty
from backend.utils.privacy_filter import PrivacySanitizingFilter

def create_app() -> Flask:
    """Create and configure the Flask application instance."""
    frontend_dir = os.path.join(PROJECT_ROOT, "frontend")
    app = Flask(__name__, static_folder=frontend_dir, static_url_path="")

    # 1. Attach Zero-Knowledge Privacy Sanitizing Filter to loggers
    privacy_filter = PrivacySanitizingFilter()
    app.logger.addFilter(privacy_filter)
    logging.getLogger("werkzeug").addFilter(privacy_filter)

    # 2. Initialize Database & Seed Baseline Anonymous Demo Metrics
    init_db()
    seed_demo_analytics_if_empty()

    # 3. Register Blueprints
    app.register_blueprint(analysis_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(generator_bp)

    # 4. Security Headers Middleware (AppSec Best Practice)
    @app.after_request
    def apply_security_headers(response):
        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent Clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # Prevent XSS
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Strict Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Cache control for API responses to prevent caching sensitive credentials
        if response.headers.get("Content-Type", "").startswith("application/json"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    # 5. Frontend Navigation Routes
    @app.route("/")
    def index():
        return send_from_directory(frontend_dir, "index.html")

    @app.route("/dashboard")
    def dashboard_page():
        return send_from_directory(frontend_dir, "dashboard.html")

    @app.route("/api/health")
    def health():
        return jsonify({
            "status": "HEALTHY",
            "application": "Password Strength Analyzer & Security Suggestion Tool",
            "mode": "Defensive Zero-Knowledge Local Analysis",
            "privacy_controls": {
                "plaintext_storage": False,
                "password_logging": False,
                "external_transmission": False
            }
        }), 200

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"\n========================================================")
    print(f"[*] Password Strength Analyzer & Security Suggestion Tool")
    print(f"[*] Defensive Zero-Knowledge Engine Active")
    print(f"[*] Server running at: http://{host}:{port}")
    print(f"[*] Dashboard at:      http://{host}:{port}/dashboard")
    print(f"========================================================\n")
    app.run(host=host, port=port, debug=True)
