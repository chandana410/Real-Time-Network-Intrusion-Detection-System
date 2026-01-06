"""
Configuration module for Network Intrusion Detection System.
Contains detection rules, thresholds, and system settings.
"""

import json
import os
from pathlib import Path


class Config:
    """Configuration class for IDS settings and detection rules."""
    
    # Default configuration
    DEFAULT_CONFIG = {
        "network": {
            "interface": "any",
            "promiscuous_mode": True,
            "packet_count": 0,  # 0 = unlimited
            "timeout": 10  # seconds
        },
        "detection": {
            "port_scan": {
                "enabled": True,
                "threshold": 10,  # ports per source IP
                "time_window": 60,  # seconds
                "suspicious_ports": [21, 22, 23, 25, 80, 443, 3306, 3389, 8080]
            },
            "brute_force": {
                "enabled": True,
                "threshold": 5,  # failed attempts
                "time_window": 300,  # seconds
                "target_ports": [21, 22, 23, 3389]  # FTP, SSH, Telnet, RDP
            },
            "malformed_packet": {
                "enabled": True,
                "check_tcp_flags": True,
                "check_packet_size": True,
                "min_packet_size": 20,
                "max_packet_size": 65535
            },
            "dos_attack": {
                "enabled": True,
                "threshold": 100,  # packets per second
                "time_window": 10  # seconds
            }
        },
        "logging": {
            "database": "intrusion_detection.db",
            "log_file": "ids.log",
            "console_output": True,
            "log_level": "INFO"
        },
        "alerts": {
            "enabled": True,
            "alert_methods": ["console", "database", "file"]
        }
    }
    
    def __init__(self, config_file=None):
        """
        Initialize configuration.
        
        Args:
            config_file: Path to custom configuration file (JSON)
        """
        self.config = self.DEFAULT_CONFIG.copy()
        
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def load_config(self, config_file):
        """
        Load configuration from JSON file.
        
        Args:
            config_file: Path to configuration file
        """
        try:
            with open(config_file, 'r') as f:
                custom_config = json.load(f)
                self._merge_config(custom_config)
        except Exception as e:
            print(f"Error loading config file: {e}")
            print("Using default configuration")
    
    def _merge_config(self, custom_config):
        """
        Merge custom configuration with defaults.
        
        Args:
            custom_config: Dictionary with custom configuration
        """
        for section, settings in custom_config.items():
            if section in self.config:
                if isinstance(settings, dict):
                    self.config[section].update(settings)
                else:
                    self.config[section] = settings
    
    def save_config(self, config_file):
        """
        Save current configuration to JSON file.
        
        Args:
            config_file: Path to save configuration
        """
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"Configuration saved to {config_file}")
        except Exception as e:
            print(f"Error saving config file: {e}")
    
    def get(self, section, key=None):
        """
        Get configuration value.
        
        Args:
            section: Configuration section
            key: Optional key within section
            
        Returns:
            Configuration value or section
        """
        if key:
            return self.config.get(section, {}).get(key)
        return self.config.get(section)
    
    def set(self, section, key, value):
        """
        Set configuration value.
        
        Args:
            section: Configuration section
            key: Key within section
            value: Value to set
        """
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
    
    def is_detection_enabled(self, detection_type):
        """
        Check if a detection type is enabled.
        
        Args:
            detection_type: Type of detection (port_scan, brute_force, etc.)
            
        Returns:
            Boolean indicating if detection is enabled
        """
        return self.config.get("detection", {}).get(detection_type, {}).get("enabled", False)
