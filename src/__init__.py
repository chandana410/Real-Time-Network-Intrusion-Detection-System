"""
Network Intrusion Detection System (IDS)
A real-time system for detecting network security threats.
"""

__version__ = "1.0.0"
__author__ = "IDS Development Team"

from .config import Config
from .database import Database
from .alert_logger import AlertLogger
from .detector import IntrusionDetector

__all__ = [
    "Config",
    "Database",
    "AlertLogger",
    "IntrusionDetector"
]
