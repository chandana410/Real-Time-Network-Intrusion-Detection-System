"""
Database module for Network Intrusion Detection System.
Handles alert logging and query operations using SQLite.
"""

import sqlite3
import threading
from datetime import datetime
from pathlib import Path


class Database:
    """Database handler for intrusion detection alerts."""
    
    def __init__(self, db_path="intrusion_detection.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.lock = threading.Lock()
        self._initialize_database()
    
    def _initialize_database(self):
        """Create database tables if they don't exist."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    description TEXT,
                    details TEXT
                )
            """)
            
            # Create statistics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_packets INTEGER,
                    suspicious_packets INTEGER,
                    alerts_triggered INTEGER
                )
            """)
            
            # Create index for faster queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON alerts(timestamp)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alert_type 
                ON alerts(alert_type)
            """)
            
            conn.commit()
            conn.close()
    
    def log_alert(self, alert_type, severity, source_ip=None, destination_ip=None,
                  source_port=None, destination_port=None, protocol=None,
                  description="", details=""):
        """
        Log a security alert to the database.
        
        Args:
            alert_type: Type of alert (port_scan, brute_force, etc.)
            severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
            source_ip: Source IP address
            destination_ip: Destination IP address
            source_port: Source port number
            destination_port: Destination port number
            protocol: Network protocol (TCP, UDP, etc.)
            description: Brief description of the alert
            details: Additional details about the alert
            
        Returns:
            Alert ID if successful, None otherwise
        """
        timestamp = datetime.now().isoformat()
        
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO alerts (
                        timestamp, alert_type, severity, source_ip, destination_ip,
                        source_port, destination_port, protocol, description, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, alert_type, severity, source_ip, destination_ip,
                      source_port, destination_port, protocol, description, details))
                
                alert_id = cursor.lastrowid
                conn.commit()
                conn.close()
                
                return alert_id
            except Exception as e:
                print(f"Error logging alert: {e}")
                return None
    
    def get_alerts(self, limit=100, alert_type=None, severity=None, 
                   start_time=None, end_time=None):
        """
        Query alerts from the database.
        
        Args:
            limit: Maximum number of alerts to retrieve
            alert_type: Filter by alert type
            severity: Filter by severity level
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            
        Returns:
            List of alert dictionaries
        """
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = "SELECT * FROM alerts WHERE 1=1"
                params = []
                
                if alert_type:
                    query += " AND alert_type = ?"
                    params.append(alert_type)
                
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                alerts = [dict(row) for row in rows]
                conn.close()
                
                return alerts
            except Exception as e:
                print(f"Error retrieving alerts: {e}")
                return []
    
    def get_alert_statistics(self, time_period="24h"):
        """
        Get alert statistics for a time period.
        
        Args:
            time_period: Time period (24h, 7d, 30d)
            
        Returns:
            Dictionary with statistics
        """
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Calculate time threshold based on period
                from datetime import timedelta
                now = datetime.now()
                
                if time_period == "24h":
                    threshold = (now - timedelta(hours=24)).isoformat()
                elif time_period == "7d":
                    threshold = (now - timedelta(days=7)).isoformat()
                elif time_period == "30d":
                    threshold = (now - timedelta(days=30)).isoformat()
                else:
                    threshold = (now - timedelta(hours=24)).isoformat()
                
                # Get total alerts
                cursor.execute("""
                    SELECT COUNT(*) FROM alerts WHERE timestamp >= ?
                """, (threshold,))
                total_alerts = cursor.fetchone()[0]
                
                # Get alerts by type
                cursor.execute("""
                    SELECT alert_type, COUNT(*) as count 
                    FROM alerts 
                    WHERE timestamp >= ?
                    GROUP BY alert_type
                """, (threshold,))
                alerts_by_type = dict(cursor.fetchall())
                
                # Get alerts by severity
                cursor.execute("""
                    SELECT severity, COUNT(*) as count 
                    FROM alerts 
                    WHERE timestamp >= ?
                    GROUP BY severity
                """, (threshold,))
                alerts_by_severity = dict(cursor.fetchall())
                
                conn.close()
                
                return {
                    "total_alerts": total_alerts,
                    "alerts_by_type": alerts_by_type,
                    "alerts_by_severity": alerts_by_severity,
                    "time_period": time_period
                }
            except Exception as e:
                print(f"Error getting statistics: {e}")
                return {}
    
    def clear_old_alerts(self, days=30):
        """
        Remove alerts older than specified days.
        
        Args:
            days: Number of days to keep alerts
            
        Returns:
            Number of deleted alerts
        """
        with self.lock:
            try:
                from datetime import timedelta
                threshold = (datetime.now() - timedelta(days=days)).isoformat()
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute("""
                    DELETE FROM alerts WHERE timestamp < ?
                """, (threshold,))
                
                deleted_count = cursor.rowcount
                conn.commit()
                conn.close()
                
                return deleted_count
            except Exception as e:
                print(f"Error clearing old alerts: {e}")
                return 0
    
    def close(self):
        """Close database connection."""
        pass  # SQLite connections are opened/closed per operation
