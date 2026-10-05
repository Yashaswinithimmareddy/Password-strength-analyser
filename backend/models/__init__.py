"""
Models package initialization.
"""
from .database import (
    init_db,
    record_analysis_metadata,
    get_dashboard_statistics,
    seed_demo_analytics_if_empty
)

__all__ = [
    "init_db",
    "record_analysis_metadata",
    "get_dashboard_statistics",
    "seed_demo_analytics_if_empty"
]
