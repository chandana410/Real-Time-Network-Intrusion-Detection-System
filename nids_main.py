#!/usr/bin/env python3
"""
Real-Time Network Intrusion Detection System (NIDS)
Monitors network packets and detects suspicious activities
"""

import socket
import struct
import sys
import logging
from datetime import datetime

class PacketAnalyzer:
    def __init__(self):
        self.suspicious_ports = [21, 22, 23, 25, 445, 3306, 3389]
        self.alert_threshold = 5
        self.connection_attempts = {}
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            filename='intrusion_alerts.log',
            level=logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def analyze_packet(self, packet_data):
        try:
            version_header_length = packet_data[0]
            header_length = (version_header_length & 15) * 4
            proto = packet_data[9]
            src_ip = self.format_ipv4(packet_data[12:16])
            dest_ip = self.format_ipv4(packet_data[16:20])
            
            if proto == 6:
                src_port, dest_port = struct.unpack('! H H', packet_data[header_length:header_length+4])
                flags = packet_data[header_length + 13]
                
                if self.detect_port_scan(src_ip, dest_port):
                    alert = f"ALERT: Port scan from {src_ip} to port {dest_port}"
                    self.logger.warning(alert)
                    print(f"\033[91m{alert}\033[0m")
                
                if flags & 0x02 and not (flags & 0x10):
                    self.logger.warning(f"ALERT: SYN flood from {src_ip}")
                    print(f"\033[91mALERT: SYN flood from {src_ip}\033[0m")
        
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {str(e)}")
    
    def detect_port_scan(self, src_ip, dest_port):
        if src_ip not in self.connection_attempts:
            self.connection_attempts[src_ip] = []
        
        self.connection_attempts[src_ip].append(dest_port)
        
        if len(self.connection_attempts[src_ip]) > self.alert_threshold:
            return True
        return False
    
    @staticmethod
    def format_ipv4(bytes_addr):
        bytes_iter = iter(bytes_addr)
        return '.'.join(map(str, bytes_iter))

class NetworkSniffer:
    def __init__(self):
        self.analyzer = PacketAnalyzer()
        self.packet_count = 0
    
    def start_sniffing(self):
        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            print("\033[92m[*] NIDS Started\033[0m")
            print(f"\033[92m[*] Time: {datetime.now()}\033[0m")
            print("\033[92m[*] Monitoring network traffic...\033[0m\n")
            
            while True:
                raw_data, addr = conn.recvfrom(65535)
                self.packet_count += 1
                
                if self.packet_count % 100 == 0:
                    print(f"\033[94m[+] Packets: {self.packet_count}\033[0m")
                
                self.analyzer.analyze_packet(raw_data[14:])
        
        except PermissionError:
            print("\033[91m[!] Requires root privileges\033[0m")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n\033[92m[*] NIDS Stopped\033[0m")
            print(f"\033[92m[*] Packets: {self.packet_count}\033[0m")
            sys.exit(0)

if __name__ == "__main__":
    sniffer = NetworkSniffer()
    sniffer.start_sniffing()
