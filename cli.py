#!/usr/bin/env python3
"""
Command-line interface for Network Intrusion Detection System.
"""

import argparse
import signal
import sys
import os
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config import Config
from database import Database
from alert_logger import AlertLogger
from detector import IntrusionDetector


class IDSCLI:
    """Command-line interface for IDS."""
    
    def __init__(self):
        """Initialize CLI."""
        self.detector = None
        self.config = None
        self.database = None
        self.alert_logger = None
    
    def setup(self, config_file=None):
        """
        Setup IDS components.
        
        Args:
            config_file: Optional configuration file path
        """
        # Load configuration
        self.config = Config(config_file)
        
        # Initialize database
        db_path = self.config.get("logging", "database")
        self.database = Database(db_path)
        
        # Initialize alert logger
        self.alert_logger = AlertLogger(self.config, self.database)
        
        # Initialize detector
        self.detector = IntrusionDetector(self.config, self.alert_logger)
    
    def start(self, config_file=None):
        """
        Start the intrusion detection system.
        
        Args:
            config_file: Optional configuration file path
        """
        try:
            self.setup(config_file)
            
            # Setup signal handlers
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            print("=" * 60)
            print("Network Intrusion Detection System")
            print("=" * 60)
            print("\nPress Ctrl+C to stop\n")
            
            # Start detection
            self.detector.start()
            
        except KeyboardInterrupt:
            self._stop()
        except Exception as e:
            print(f"Error starting IDS: {e}")
            sys.exit(1)
    
    def _signal_handler(self, sig, frame):
        """Handle interrupt signals."""
        self._stop()
    
    def _stop(self):
        """Stop the IDS."""
        if self.detector:
            print("\n\nShutting down...")
            self.detector.stop()
            
            # Print statistics
            stats = self.detector.get_statistics()
            print("\n" + "=" * 60)
            print("Session Statistics")
            print("=" * 60)
            print(f"Total packets processed: {stats['total_packets']}")
            print(f"Suspicious packets: {stats['suspicious_packets']}")
            print(f"Alerts triggered: {stats['alerts_triggered']}")
            print("=" * 60)
        
        sys.exit(0)
    
    def show_stats(self, config_file=None, period="24h"):
        """
        Show alert statistics.
        
        Args:
            config_file: Optional configuration file path
            period: Time period (24h, 7d, 30d)
        """
        self.setup(config_file)
        
        print("=" * 60)
        print(f"Alert Statistics ({period})")
        print("=" * 60)
        
        stats = self.database.get_alert_statistics(period)
        
        print(f"\nTotal Alerts: {stats.get('total_alerts', 0)}")
        
        print("\nAlerts by Type:")
        for alert_type, count in stats.get('alerts_by_type', {}).items():
            print(f"  {alert_type}: {count}")
        
        print("\nAlerts by Severity:")
        for severity, count in stats.get('alerts_by_severity', {}).items():
            print(f"  {severity}: {count}")
        
        print("=" * 60)
    
    def show_alerts(self, config_file=None, limit=20, alert_type=None, severity=None):
        """
        Show recent alerts.
        
        Args:
            config_file: Optional configuration file path
            limit: Maximum number of alerts to show
            alert_type: Filter by alert type
            severity: Filter by severity
        """
        self.setup(config_file)
        
        print("=" * 60)
        print("Recent Alerts")
        print("=" * 60)
        
        alerts = self.database.get_alerts(
            limit=limit,
            alert_type=alert_type,
            severity=severity
        )
        
        if not alerts:
            print("\nNo alerts found.")
        else:
            for alert in alerts:
                print(f"\n[{alert['timestamp']}] [{alert['severity']}] {alert['alert_type']}")
                if alert['source_ip']:
                    print(f"  Source: {alert['source_ip']}", end="")
                    if alert['source_port']:
                        print(f":{alert['source_port']}", end="")
                    print()
                if alert['destination_ip']:
                    print(f"  Destination: {alert['destination_ip']}", end="")
                    if alert['destination_port']:
                        print(f":{alert['destination_port']}", end="")
                    print()
                if alert['description']:
                    print(f"  Description: {alert['description']}")
                if alert['details']:
                    print(f"  Details: {alert['details']}")
        
        print("\n" + "=" * 60)
    
    def clear_alerts(self, config_file=None, days=30):
        """
        Clear old alerts from database.
        
        Args:
            config_file: Optional configuration file path
            days: Clear alerts older than this many days
        """
        self.setup(config_file)
        
        print(f"Clearing alerts older than {days} days...")
        deleted = self.database.clear_old_alerts(days)
        print(f"Deleted {deleted} old alerts.")
    
    def save_config(self, config_file="config.json"):
        """
        Save default configuration to file.
        
        Args:
            config_file: Configuration file path
        """
        config = Config()
        config.save_config(config_file)
        print(f"Default configuration saved to {config_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s start                    Start IDS with default configuration
  %(prog)s start -c config.json     Start IDS with custom configuration
  %(prog)s stats                    Show alert statistics (last 24 hours)
  %(prog)s stats --period 7d        Show statistics for last 7 days
  %(prog)s alerts                   Show recent alerts
  %(prog)s alerts --limit 50        Show last 50 alerts
  %(prog)s clear --days 60          Clear alerts older than 60 days
  %(prog)s save-config              Save default configuration
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start intrusion detection')
    start_parser.add_argument('-c', '--config', help='Configuration file path')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show alert statistics')
    stats_parser.add_argument('-c', '--config', help='Configuration file path')
    stats_parser.add_argument('--period', default='24h', choices=['24h', '7d', '30d'],
                             help='Time period for statistics')
    
    # Alerts command
    alerts_parser = subparsers.add_parser('alerts', help='Show recent alerts')
    alerts_parser.add_argument('-c', '--config', help='Configuration file path')
    alerts_parser.add_argument('--limit', type=int, default=20, help='Number of alerts to show')
    alerts_parser.add_argument('--type', help='Filter by alert type')
    alerts_parser.add_argument('--severity', help='Filter by severity')
    
    # Clear command
    clear_parser = subparsers.add_parser('clear', help='Clear old alerts')
    clear_parser.add_argument('-c', '--config', help='Configuration file path')
    clear_parser.add_argument('--days', type=int, default=30, 
                             help='Clear alerts older than this many days')
    
    # Save config command
    save_parser = subparsers.add_parser('save-config', help='Save default configuration')
    save_parser.add_argument('-o', '--output', default='config.json',
                            help='Output configuration file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    cli = IDSCLI()
    
    try:
        if args.command == 'start':
            cli.start(args.config)
        elif args.command == 'stats':
            cli.show_stats(args.config, args.period)
        elif args.command == 'alerts':
            cli.show_alerts(args.config, args.limit, args.type, args.severity)
        elif args.command == 'clear':
            cli.clear_alerts(args.config, args.days)
        elif args.command == 'save-config':
            cli.save_config(args.output)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
