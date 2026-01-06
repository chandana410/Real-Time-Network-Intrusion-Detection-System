"""
Alert logging module for Network Intrusion Detection System.
Handles real-time alert notifications and logging.
"""

import logging
from datetime import datetime
from pathlib import Path


class AlertLogger:
    """Handles alert logging and notifications."""
    
    # ANSI color codes for console output
    COLORS = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[94m",    # Blue
        "LOW": "\033[92m",       # Green
        "RESET": "\033[0m"       # Reset
    }
    
    def __init__(self, config, database):
        """
        Initialize alert logger.
        
        Args:
            config: Configuration object
            database: Database object for logging
        """
        self.config = config
        self.database = database
        self.console_output = config.get("logging", "console_output")
        self.log_file = config.get("logging", "log_file")
        
        # Setup file logging
        self._setup_file_logging()
    
    def _setup_file_logging(self):
        """Setup file logging."""
        if self.log_file:
            logging.basicConfig(
                filename=self.log_file,
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
    
    def log_alert(self, alert_type, severity, source_ip=None, destination_ip=None,
                  source_port=None, destination_port=None, protocol=None,
                  description="", details=""):
        """
        Log an alert using configured methods.
        
        Args:
            alert_type: Type of alert
            severity: Severity level
            source_ip: Source IP address
            destination_ip: Destination IP address
            source_port: Source port
            destination_port: Destination port
            protocol: Protocol used
            description: Alert description
            details: Additional details
        """
        # Log to database
        alert_id = self.database.log_alert(
            alert_type=alert_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            description=description,
            details=details
        )
        
        # Format alert message
        alert_msg = self._format_alert(
            alert_id, alert_type, severity, source_ip, destination_ip,
            source_port, destination_port, protocol, description
        )
        
        # Log to console
        if self.console_output:
            self._log_to_console(alert_msg, severity)
        
        # Log to file
        if self.log_file:
            logging.info(alert_msg)
    
    def _format_alert(self, alert_id, alert_type, severity, source_ip, 
                     destination_ip, source_port, destination_port, 
                     protocol, description):
        """
        Format alert message.
        
        Args:
            alert_id: Alert ID
            alert_type: Type of alert
            severity: Severity level
            source_ip: Source IP
            destination_ip: Destination IP
            source_port: Source port
            destination_port: Destination port
            protocol: Protocol
            description: Description
            
        Returns:
            Formatted alert message
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        msg_parts = [
            f"[{timestamp}]",
            f"[{severity}]",
            f"[{alert_type.upper()}]"
        ]
        
        if source_ip:
            msg_parts.append(f"Source: {source_ip}")
            if source_port:
                msg_parts[-1] += f":{source_port}"
        
        if destination_ip:
            msg_parts.append(f"Dest: {destination_ip}")
            if destination_port:
                msg_parts[-1] += f":{destination_port}"
        
        if protocol:
            msg_parts.append(f"Proto: {protocol}")
        
        if description:
            msg_parts.append(description)
        
        return " | ".join(msg_parts)
    
    def _log_to_console(self, message, severity):
        """
        Log message to console with color coding.
        
        Args:
            message: Message to log
            severity: Severity level for color coding
        """
        color = self.COLORS.get(severity, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]
        print(f"{color}{message}{reset}")
    
    def log_info(self, message):
        """
        Log informational message.
        
        Args:
            message: Message to log
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{timestamp}] [INFO] {message}"
        
        if self.console_output:
            print(msg)
        
        if self.log_file:
            logging.info(message)
    
    def log_error(self, message):
        """
        Log error message.
        
        Args:
            message: Error message to log
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{timestamp}] [ERROR] {message}"
        
        if self.console_output:
            color = self.COLORS["CRITICAL"]
            reset = self.COLORS["RESET"]
            print(f"{color}{msg}{reset}")
        
        if self.log_file:
            logging.error(message)
