# Installation Guide - Real-Time Network Intrusion Detection System (NIDS)

## Prerequisites
- Python 3.7 or higher
- Linux/Unix system (for full functionality)
- Administrator/Root privileges (for packet capture)
- pip package manager

## Step 1: Clone the Repository
```bash
git clone https://github.com/chandana410/Real-Time-Network-Intrusion-Detection-System.git
cd Real-Time-Network-Intrusion-Detection-System
```

## Step 2: Install Dependencies
```bash
# Install required packages
pip install -r requirements.txt

# Or manually install optional packages for enhanced functionality
pip install scapy pynpcap pandas matplotlib pytest
```

## Step 3: Run the NIDS
```bash
# Start the intrusion detection system (requires root)
sudo python3 nids_main.py
```

## Step 4: Test with Attack Simulator
```bash
# In another terminal, run the attack simulator
python3 attack_simulator.py
```

## Features Detected
- Port Scanning Attacks
- SYN Flood Attacks  
- Brute Force Attempts
- Malformed Packets
- Suspicious Network Patterns

## Alert Storage
All detected intrusions are logged to:
- `intrusion_alerts.log` - Text log file
- `intrusion_alerts.db` - SQLite database

## Troubleshooting
- Ensure you run with sudo for packet capture
- Check file permissions if database errors occur
- Verify network interface is active
