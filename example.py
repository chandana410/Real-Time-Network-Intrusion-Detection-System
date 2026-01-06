#!/usr/bin/env python3
"""
Example usage of the Network Intrusion Detection System.
This script demonstrates how to use the IDS programmatically.
"""

import sys
import os
import time

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config import Config
from database import Database
from alert_logger import AlertLogger
from detector import IntrusionDetector


def main():
    """Example of programmatic IDS usage."""
    
    print("=" * 60)
    print("Network Intrusion Detection System - Example Usage")
    print("=" * 60)
    
    # 1. Create configuration
    print("\n1. Loading configuration...")
    config = Config()
    
    # Optionally customize configuration
    config.set("detection", "port_scan", {
        "enabled": True,
        "threshold": 10,
        "time_window": 60
    })
    
    # 2. Initialize database
    print("2. Initializing database...")
    database = Database("example_ids.db")
    
    # 3. Create alert logger
    print("3. Setting up alert logger...")
    alert_logger = AlertLogger(config, database)
    
    # 4. Initialize detector
    print("4. Initializing intrusion detector...")
    detector = IntrusionDetector(config, alert_logger)
    
    # 5. Example: Log a test alert
    print("\n5. Testing alert logging...")
    alert_logger.log_alert(
        alert_type="test_alert",
        severity="MEDIUM",
        source_ip="192.168.1.100",
        destination_ip="192.168.1.1",
        source_port=54321,
        destination_port=80,
        protocol="TCP",
        description="Example test alert",
        details="This is a demonstration alert"
    )
    
    # 6. Query alerts
    print("\n6. Querying alerts...")
    alerts = database.get_alerts(limit=5)
    print(f"Found {len(alerts)} alert(s)")
    
    for alert in alerts:
        print(f"\n  Alert ID: {alert['id']}")
        print(f"  Type: {alert['alert_type']}")
        print(f"  Severity: {alert['severity']}")
        print(f"  Time: {alert['timestamp']}")
    
    # 7. Get statistics
    print("\n7. Getting statistics...")
    stats = database.get_alert_statistics("24h")
    print(f"Total alerts (24h): {stats['total_alerts']}")
    
    # 8. Note about starting detection
    print("\n" + "=" * 60)
    print("Note: To start actual packet capture, run:")
    print("  sudo python3 cli.py start")
    print("\nPacket capture requires root/administrator privileges.")
    print("=" * 60)
    
    # Cleanup
    print("\nExample completed successfully!")


if __name__ == '__main__':
    main()
