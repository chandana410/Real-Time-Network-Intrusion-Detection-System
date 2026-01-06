#!/usr/bin/env python3
"""
Attack Simulator for Testing NIDS
Simulates various network attacks to test detection
"""

import socket
import time
import random
from datetime import datetime

class AttackSimulator:
    def __init__(self, target_ip='127.0.0.1'):
        self.target_ip = target_ip
        self.attacks_simulated = 0
    
    def port_scan_simulation(self, ports=[21, 22, 23, 25, 445]):
        """Simulate port scanning attack"""
        print(f"[*] Simulating port scan on {self.target_ip}")
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    print(f"  Port {port}: OPEN")
                sock.close()
                time.sleep(0.1)
                self.attacks_simulated += 1
            except Exception as e:
                pass
    
    def syn_flood_simulation(self, target_port=80, num_packets=10):
        """Simulate SYN flood attack (benign version)"""
        print(f"[*] Simulating SYN flood on {self.target_ip}:{target_port}")
        for i in range(num_packets):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                sock.connect_ex((self.target_ip, target_port))
                sock.close()
                print(f"  SYN packet {i+1}/{num_packets} sent")
                time.sleep(0.05)
                self.attacks_simulated += 1
            except:
                pass
    
    def brute_force_simulation(self, target_port=22, attempts=5):
        """Simulate brute force login attempts"""
        print(f"[*] Simulating brute force on {self.target_ip}:{target_port}")
        usernames = ['admin', 'root', 'user', 'test']
        for i in range(attempts):
            username = random.choice(usernames)
            print(f"  Attempt {i+1}: {username}@{self.target_ip}:{target_port}")
            time.sleep(0.2)
            self.attacks_simulated += 1
    
    def malformed_packet_simulation(self):
        """Simulate sending malformed packets"""
        print(f"[*] Simulating malformed packets")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            malformed_data = b'MALFORMED' * 100
            print(f"  Sending {len(malformed_data)} bytes of malformed data")
            self.attacks_simulated += 1
        except PermissionError:
            print("  [!] Requires root privileges")
    
    def run_all_simulations(self):
        """Run all attack simulations"""
        print(f"\n[+] Starting Attack Simulations at {datetime.now()}\n")
        self.port_scan_simulation()
        time.sleep(1)
        self.syn_flood_simulation()
        time.sleep(1)
        self.brute_force_simulation()
        time.sleep(1)
        self.malformed_packet_simulation()
        print(f"\n[+] Simulations Complete: {self.attacks_simulated} attacks simulated\n")

if __name__ == "__main__":
    simulator = AttackSimulator()
    simulator.run_all_simulations()
