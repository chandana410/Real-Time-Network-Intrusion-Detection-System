"""
Main detector module for Network Intrusion Detection System.
Captures and analyzes network packets for suspicious patterns.
"""

import time
from collections import defaultdict
from datetime import datetime, timedelta
from threading import Thread, Lock

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")


class IntrusionDetector:
    """Main intrusion detection engine."""
    
    def __init__(self, config, alert_logger):
        """
        Initialize intrusion detector.
        
        Args:
            config: Configuration object
            alert_logger: Alert logger object
        """
        self.config = config
        self.alert_logger = alert_logger
        self.running = False
        self.lock = Lock()
        
        # Tracking data structures
        self.port_scan_tracker = defaultdict(lambda: {"ports": set(), "first_seen": None})
        self.brute_force_tracker = defaultdict(lambda: {"attempts": 0, "first_seen": None})
        self.dos_tracker = defaultdict(lambda: {"count": 0, "first_seen": None})
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "suspicious_packets": 0,
            "alerts_triggered": 0
        }
        
        if not SCAPY_AVAILABLE:
            self.alert_logger.log_error("Scapy is not installed. Packet capture will not work.")
    
    def start(self):
        """Start the intrusion detection system."""
        if not SCAPY_AVAILABLE:
            self.alert_logger.log_error("Cannot start: Scapy is not available")
            return False
        
        if self.running:
            self.alert_logger.log_info("Detector is already running")
            return False
        
        self.running = True
        self.alert_logger.log_info("Starting Network Intrusion Detection System...")
        
        # Start cleanup thread
        cleanup_thread = Thread(target=self._cleanup_old_entries, daemon=True)
        cleanup_thread.start()
        
        # Start packet capture
        interface = self.config.get("network", "interface")
        packet_count = self.config.get("network", "packet_count")
        
        try:
            self.alert_logger.log_info(f"Capturing packets on interface: {interface}")
            sniff(
                iface=interface if interface != "any" else None,
                prn=self._process_packet,
                store=False,
                count=packet_count if packet_count > 0 else 0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.alert_logger.log_error(f"Error during packet capture: {e}")
            self.running = False
            return False
        
        return True
    
    def stop(self):
        """Stop the intrusion detection system."""
        if self.running:
            self.running = False
            self.alert_logger.log_info("Stopping Network Intrusion Detection System...")
            return True
        return False
    
    def _process_packet(self, packet):
        """
        Process a captured packet.
        
        Args:
            packet: Captured network packet
        """
        try:
            with self.lock:
                self.stats["total_packets"] += 1
            
            # Check if packet has IP layer
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Detect malformed packets
            if self.config.is_detection_enabled("malformed_packet"):
                self._detect_malformed_packet(packet)
            
            # Detect port scanning
            if self.config.is_detection_enabled("port_scan"):
                if packet.haslayer(TCP) or packet.haslayer(UDP):
                    self._detect_port_scan(packet)
            
            # Detect brute force attacks
            if self.config.is_detection_enabled("brute_force"):
                if packet.haslayer(TCP):
                    self._detect_brute_force(packet)
            
            # Detect DoS attacks
            if self.config.is_detection_enabled("dos_attack"):
                self._detect_dos_attack(packet)
        
        except Exception as e:
            self.alert_logger.log_error(f"Error processing packet: {e}")
    
    def _detect_port_scan(self, packet):
        """
        Detect port scanning activity.
        
        Args:
            packet: Network packet to analyze
        """
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        
        # Get destination port
        dst_port = None
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
        
        if not dst_port:
            return
        
        # Track ports accessed by this source IP
        tracker = self.port_scan_tracker[src_ip]
        
        if tracker["first_seen"] is None:
            tracker["first_seen"] = datetime.now()
        
        tracker["ports"].add(dst_port)
        
        # Check threshold
        threshold = self.config.get("detection", "port_scan").get("threshold", 10)
        time_window = self.config.get("detection", "port_scan").get("time_window", 60)
        
        time_diff = (datetime.now() - tracker["first_seen"]).total_seconds()
        
        if len(tracker["ports"]) >= threshold and time_diff <= time_window:
            # Port scan detected
            with self.lock:
                self.stats["suspicious_packets"] += 1
                self.stats["alerts_triggered"] += 1
            
            self.alert_logger.log_alert(
                alert_type="port_scan",
                severity="HIGH",
                source_ip=src_ip,
                destination_ip=ip_layer.dst,
                destination_port=dst_port,
                protocol="TCP" if packet.haslayer(TCP) else "UDP",
                description=f"Port scan detected: {len(tracker['ports'])} ports scanned in {time_diff:.1f}s",
                details=f"Ports scanned: {sorted(list(tracker['ports']))[:20]}"
            )
            
            # Reset tracker
            self.port_scan_tracker[src_ip] = {"ports": set(), "first_seen": None}
    
    def _detect_brute_force(self, packet):
        """
        Detect brute force attack attempts.
        
        Args:
            packet: Network packet to analyze
        """
        if not packet.haslayer(TCP):
            return
        
        tcp_layer = packet[TCP]
        ip_layer = packet[IP]
        
        # Check for connection attempts to sensitive ports
        target_ports = self.config.get("detection", "brute_force").get("target_ports", [])
        
        if tcp_layer.dport not in target_ports:
            return
        
        # Check for SYN or RST flags (connection attempts/failures)
        if tcp_layer.flags & 0x02 or tcp_layer.flags & 0x04:  # SYN or RST
            key = f"{ip_layer.src}:{tcp_layer.dport}"
            tracker = self.brute_force_tracker[key]
            
            if tracker["first_seen"] is None:
                tracker["first_seen"] = datetime.now()
            
            tracker["attempts"] += 1
            
            # Check threshold
            threshold = self.config.get("detection", "brute_force").get("threshold", 5)
            time_window = self.config.get("detection", "brute_force").get("time_window", 300)
            
            time_diff = (datetime.now() - tracker["first_seen"]).total_seconds()
            
            if tracker["attempts"] >= threshold and time_diff <= time_window:
                # Brute force detected
                with self.lock:
                    self.stats["suspicious_packets"] += 1
                    self.stats["alerts_triggered"] += 1
                
                self.alert_logger.log_alert(
                    alert_type="brute_force",
                    severity="CRITICAL",
                    source_ip=ip_layer.src,
                    destination_ip=ip_layer.dst,
                    destination_port=tcp_layer.dport,
                    protocol="TCP",
                    description=f"Brute force attack detected: {tracker['attempts']} attempts in {time_diff:.1f}s",
                    details=f"Target port: {tcp_layer.dport}"
                )
                
                # Reset tracker
                self.brute_force_tracker[key] = {"attempts": 0, "first_seen": None}
    
    def _detect_malformed_packet(self, packet):
        """
        Detect malformed or suspicious packets.
        
        Args:
            packet: Network packet to analyze
        """
        suspicious = False
        reason = []
        
        # Check TCP flags
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags
            
            # Check for invalid flag combinations
            if flags & 0x3F == 0:  # No flags set (NULL scan)
                suspicious = True
                reason.append("NULL scan (no TCP flags)")
            elif (flags & 0x29) == 0x29:  # FIN + PSH + URG (XMAS scan)
                suspicious = True
                reason.append("XMAS scan (FIN+PSH+URG flags set)")
            elif (flags & 0x02) and (flags & 0x01):  # SYN + FIN
                suspicious = True
                reason.append("Invalid TCP flags (SYN+FIN)")
        
        # Check packet size
        packet_len = len(packet)
        min_size = self.config.get("detection", "malformed_packet").get("min_packet_size", 20)
        max_size = self.config.get("detection", "malformed_packet").get("max_packet_size", 65535)
        
        if packet_len < min_size or packet_len > max_size:
            suspicious = True
            reason.append(f"Unusual packet size: {packet_len} bytes")
        
        if suspicious:
            with self.lock:
                self.stats["suspicious_packets"] += 1
                self.stats["alerts_triggered"] += 1
            
            ip_layer = packet[IP] if packet.haslayer(IP) else None
            
            self.alert_logger.log_alert(
                alert_type="malformed_packet",
                severity="MEDIUM",
                source_ip=ip_layer.src if ip_layer else None,
                destination_ip=ip_layer.dst if ip_layer else None,
                protocol="TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER",
                description="Malformed or suspicious packet detected",
                details="; ".join(reason)
            )
    
    def _detect_dos_attack(self, packet):
        """
        Detect Denial of Service (DoS) attacks.
        
        Args:
            packet: Network packet to analyze
        """
        if not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        
        tracker = self.dos_tracker[src_ip]
        
        if tracker["first_seen"] is None:
            tracker["first_seen"] = datetime.now()
        
        tracker["count"] += 1
        
        # Check threshold
        threshold = self.config.get("detection", "dos_attack").get("threshold", 100)
        time_window = self.config.get("detection", "dos_attack").get("time_window", 10)
        
        time_diff = (datetime.now() - tracker["first_seen"]).total_seconds()
        
        if tracker["count"] >= threshold and time_diff <= time_window:
            packets_per_sec = tracker["count"] / time_diff if time_diff > 0 else 0
            
            # DoS attack detected
            with self.lock:
                self.stats["suspicious_packets"] += tracker["count"]
                self.stats["alerts_triggered"] += 1
            
            self.alert_logger.log_alert(
                alert_type="dos_attack",
                severity="CRITICAL",
                source_ip=src_ip,
                destination_ip=ip_layer.dst,
                protocol="TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP",
                description=f"DoS attack detected: {packets_per_sec:.1f} packets/sec",
                details=f"Total packets: {tracker['count']} in {time_diff:.1f}s"
            )
            
            # Reset tracker
            self.dos_tracker[src_ip] = {"count": 0, "first_seen": None}
    
    def _cleanup_old_entries(self):
        """Periodically cleanup old tracking entries."""
        while self.running:
            time.sleep(60)  # Run every minute
            
            now = datetime.now()
            
            # Cleanup port scan tracker
            for src_ip in list(self.port_scan_tracker.keys()):
                tracker = self.port_scan_tracker[src_ip]
                if tracker["first_seen"] and (now - tracker["first_seen"]).total_seconds() > 300:
                    del self.port_scan_tracker[src_ip]
            
            # Cleanup brute force tracker
            for key in list(self.brute_force_tracker.keys()):
                tracker = self.brute_force_tracker[key]
                if tracker["first_seen"] and (now - tracker["first_seen"]).total_seconds() > 600:
                    del self.brute_force_tracker[key]
            
            # Cleanup DoS tracker
            for src_ip in list(self.dos_tracker.keys()):
                tracker = self.dos_tracker[src_ip]
                if tracker["first_seen"] and (now - tracker["first_seen"]).total_seconds() > 60:
                    del self.dos_tracker[src_ip]
    
    def get_statistics(self):
        """
        Get current detection statistics.
        
        Returns:
            Dictionary with statistics
        """
        with self.lock:
            return self.stats.copy()
