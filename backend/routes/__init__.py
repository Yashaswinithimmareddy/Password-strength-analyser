"""
Routes package initialization.
"""
from .analysis_routes import analysis_bp
from .dashboard_routes import dashboard_bp
from .generator_routes import generator_bp

__all__ = ["analysis_bp", "dashboard_bp", "generator_bp"]
