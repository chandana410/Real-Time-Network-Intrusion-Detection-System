#!/usr/bin/env python3
"""
Database Module for Intrusion Detection Alerts
Stores and manages intrusion detection events
"""

import sqlite3
from datetime import datetime
from typing import List, Dict

class AlertDatabase:
    def __init__(self, db_name='intrusion_alerts.db'):
        self.db_name = db_name
        self.conn = None
        self.init_database()
    
    def init_database(self):
        """Initialize database with alerts table"""
        self.conn = sqlite3.connect(self.db_name)
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                severity TEXT,
                description TEXT
            )
        ''')
        self.conn.commit()
    
    def log_alert(self, alert_type: str, src_ip: str, dst_ip: str,
                  src_port: int, dst_port: int, severity: str, desc: str):
        """Log intrusion alert to database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO alerts
                (timestamp, alert_type, source_ip, dest_ip, source_port, dest_port, severity, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), alert_type, src_ip, dst_ip,
                  src_port, dst_port, severity, desc))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Database error: {str(e)}")
            return False
    
    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent alerts"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_alerts_by_ip(self, ip_addr: str) -> List[Dict]:
        """Get all alerts for specific IP address"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM alerts WHERE source_ip = ? ORDER BY timestamp DESC', (ip_addr,))
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_high_severity_alerts(self) -> List[Dict]:
        """Get critical severity alerts"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM alerts WHERE severity = "CRITICAL" ORDER BY timestamp DESC')
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
