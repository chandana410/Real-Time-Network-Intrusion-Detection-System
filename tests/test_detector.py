"""
Testing module for Network Intrusion Detection System.
Includes simulation of various attack types for testing.
"""

import unittest
import time
import threading
from datetime import datetime

try:
    from scapy.all import IP, TCP, UDP, send, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from config import Config
from database import Database
from alert_logger import AlertLogger
from detector import IntrusionDetector


class AttackSimulator:
    """Simulates various network attacks for testing."""
    
    @staticmethod
    def simulate_port_scan(target_ip="127.0.0.1", num_ports=15):
        """
        Simulate a port scan attack.
        
        Args:
            target_ip: Target IP address
            num_ports: Number of ports to scan
        """
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Cannot simulate port scan.")
            return
        
        print(f"Simulating port scan: {num_ports} ports on {target_ip}")
        
        for port in range(20, 20 + num_ports):
            try:
                packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
                send(packet, verbose=False)
                time.sleep(0.1)
            except Exception as e:
                print(f"Error sending packet: {e}")
    
    @staticmethod
    def simulate_brute_force(target_ip="127.0.0.1", target_port=22, attempts=10):
        """
        Simulate a brute force attack.
        
        Args:
            target_ip: Target IP address
            target_port: Target port (SSH, FTP, etc.)
            attempts: Number of connection attempts
        """
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Cannot simulate brute force.")
            return
        
        print(f"Simulating brute force: {attempts} attempts on {target_ip}:{target_port}")
        
        for i in range(attempts):
            try:
                # Simulate failed connection (SYN followed by RST)
                packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
                send(packet, verbose=False)
                
                time.sleep(0.5)
                
                packet = IP(dst=target_ip) / TCP(dport=target_port, flags="R")
                send(packet, verbose=False)
                
                time.sleep(0.5)
            except Exception as e:
                print(f"Error sending packet: {e}")
    
    @staticmethod
    def simulate_malformed_packets(target_ip="127.0.0.1"):
        """
        Simulate malformed packet attacks.
        
        Args:
            target_ip: Target IP address
        """
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Cannot simulate malformed packets.")
            return
        
        print(f"Simulating malformed packets to {target_ip}")
        
        try:
            # NULL scan (no flags)
            packet = IP(dst=target_ip) / TCP(dport=80, flags=0)
            send(packet, verbose=False)
            time.sleep(0.5)
            
            # XMAS scan (FIN + PSH + URG)
            packet = IP(dst=target_ip) / TCP(dport=80, flags="FPU")
            send(packet, verbose=False)
            time.sleep(0.5)
            
            # SYN+FIN (invalid combination)
            packet = IP(dst=target_ip) / TCP(dport=80, flags="SF")
            send(packet, verbose=False)
            time.sleep(0.5)
        except Exception as e:
            print(f"Error sending packet: {e}")
    
    @staticmethod
    def simulate_dos_attack(target_ip="127.0.0.1", num_packets=150):
        """
        Simulate a DoS attack.
        
        Args:
            target_ip: Target IP address
            num_packets: Number of packets to send
        """
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Cannot simulate DoS attack.")
            return
        
        print(f"Simulating DoS attack: {num_packets} packets to {target_ip}")
        
        try:
            for i in range(num_packets):
                packet = IP(dst=target_ip) / TCP(dport=80, flags="S")
                send(packet, verbose=False)
                time.sleep(0.01)  # Send quickly
        except Exception as e:
            print(f"Error sending packet: {e}")


class TestIntrusionDetector(unittest.TestCase):
    """Test cases for intrusion detection system."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        cls.config = Config()
        cls.database = Database("test_ids.db")
        cls.alert_logger = AlertLogger(cls.config, cls.database)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        import os
        if os.path.exists("test_ids.db"):
            os.remove("test_ids.db")
    
    def test_config_loading(self):
        """Test configuration loading."""
        config = Config()
        self.assertIsNotNone(config.get("network"))
        self.assertIsNotNone(config.get("detection"))
        self.assertTrue(config.is_detection_enabled("port_scan"))
    
    def test_database_alert_logging(self):
        """Test database alert logging."""
        alert_id = self.database.log_alert(
            alert_type="test_alert",
            severity="MEDIUM",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            description="Test alert"
        )
        self.assertIsNotNone(alert_id)
        
        # Retrieve alert
        alerts = self.database.get_alerts(limit=1)
        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0]["alert_type"], "test_alert")
    
    def test_alert_statistics(self):
        """Test alert statistics retrieval."""
        stats = self.database.get_alert_statistics("24h")
        self.assertIsNotNone(stats)
        self.assertIn("total_alerts", stats)
    
    def test_detector_initialization(self):
        """Test detector initialization."""
        detector = IntrusionDetector(self.config, self.alert_logger)
        self.assertIsNotNone(detector)
        self.assertFalse(detector.running)
    
    def test_detector_statistics(self):
        """Test detector statistics."""
        detector = IntrusionDetector(self.config, self.alert_logger)
        stats = detector.get_statistics()
        self.assertIn("total_packets", stats)
        self.assertIn("suspicious_packets", stats)
        self.assertIn("alerts_triggered", stats)


class TestAttackSimulation(unittest.TestCase):
    """Test attack simulation capabilities."""
    
    def test_simulator_availability(self):
        """Test if attack simulator is available."""
        simulator = AttackSimulator()
        self.assertIsNotNone(simulator)
    
    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_port_scan_simulation(self):
        """Test port scan simulation (requires root/admin)."""
        # This test requires elevated privileges
        # It's included for documentation but may not run in all environments
        try:
            AttackSimulator.simulate_port_scan(num_ports=5)
        except Exception as e:
            self.skipTest(f"Cannot run port scan simulation: {e}")


def run_manual_tests():
    """Run manual tests with attack simulations."""
    print("=" * 60)
    print("Manual Attack Simulation Tests")
    print("=" * 60)
    print("\nNote: These tests require elevated privileges (root/admin)")
    print("to send raw packets.\n")
    
    if not SCAPY_AVAILABLE:
        print("ERROR: Scapy is not installed. Install with: pip install scapy")
        return
    
    simulator = AttackSimulator()
    
    while True:
        print("\nSelect test to run:")
        print("1. Port Scan Simulation")
        print("2. Brute Force Simulation")
        print("3. Malformed Packets Simulation")
        print("4. DoS Attack Simulation")
        print("5. Run All Simulations")
        print("0. Exit")
        
        choice = input("\nEnter choice: ").strip()
        
        if choice == "0":
            break
        elif choice == "1":
            target = input("Target IP (default: 127.0.0.1): ").strip() or "127.0.0.1"
            simulator.simulate_port_scan(target)
        elif choice == "2":
            target = input("Target IP (default: 127.0.0.1): ").strip() or "127.0.0.1"
            port = input("Target port (default: 22): ").strip() or "22"
            simulator.simulate_brute_force(target, int(port))
        elif choice == "3":
            target = input("Target IP (default: 127.0.0.1): ").strip() or "127.0.0.1"
            simulator.simulate_malformed_packets(target)
        elif choice == "4":
            target = input("Target IP (default: 127.0.0.1): ").strip() or "127.0.0.1"
            simulator.simulate_dos_attack(target)
        elif choice == "5":
            target = input("Target IP (default: 127.0.0.1): ").strip() or "127.0.0.1"
            print("\nRunning all simulations...")
            simulator.simulate_port_scan(target, 12)
            time.sleep(2)
            simulator.simulate_brute_force(target, 22, 8)
            time.sleep(2)
            simulator.simulate_malformed_packets(target)
            time.sleep(2)
            print("\nAll simulations completed!")
        else:
            print("Invalid choice!")
    
    print("\nTests completed!")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--manual':
        # Run manual tests
        run_manual_tests()
    else:
        # Run unit tests
        unittest.main()
