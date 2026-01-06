# Real-Time Network Intrusion Detection System

A comprehensive real-time network intrusion detection system (IDS) built with Python that monitors network traffic, detects suspicious activities, and provides real-time alerts for various security threats.

## Features

### Detection Capabilities
- **Port Scanning Detection**: Identifies port scanning attempts by tracking connection attempts to multiple ports from a single source
- **Brute Force Attack Detection**: Detects repeated authentication attempts to sensitive services (SSH, FTP, Telnet, RDP)
- **Malformed Packet Detection**: Identifies suspicious packets with invalid TCP flags or unusual characteristics
- **DoS Attack Detection**: Monitors for abnormally high packet rates from individual sources

### System Components
- **Main Detector Module** (`detector.py`): Core packet capture and analysis engine using Scapy
- **Configuration Module** (`config.py`): Flexible rule-based configuration system with JSON support
- **Database Module** (`database.py`): SQLite-based alert logging and query system
- **Alert Logger** (`alert_logger.py`): Real-time alert notifications with colored console output
- **Command-Line Interface** (`cli.py`): User-friendly CLI for system management
- **Testing Module** (`test_detector.py`): Attack simulation and unit tests

## Installation

### Prerequisites
- Python 3.7 or higher
- Root/Administrator privileges (required for packet capture)
- Linux, macOS, or Windows

### Steps

1. Clone the repository:
```bash
git clone https://github.com/chandana410/Real-Time-Network-Intrusion-Detection-System.git
cd Real-Time-Network-Intrusion-Detection-System
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Make the CLI executable (Linux/macOS):
```bash
chmod +x cli.py
```

## Usage

### Starting the IDS

Run with default configuration:
```bash
sudo python3 cli.py start
```

Run with custom configuration:
```bash
sudo python3 cli.py start -c custom_config.json
```

### Viewing Statistics

Show statistics for the last 24 hours:
```bash
python3 cli.py stats
```

Show statistics for the last 7 days:
```bash
python3 cli.py stats --period 7d
```

### Viewing Alerts

Show the 20 most recent alerts:
```bash
python3 cli.py alerts
```

Show 50 alerts with filtering:
```bash
python3 cli.py alerts --limit 50 --type port_scan --severity HIGH
```

### Managing Alerts

Clear alerts older than 60 days:
```bash
python3 cli.py clear --days 60
```

### Configuration Management

Save default configuration to a file:
```bash
python3 cli.py save-config -o my_config.json
```

## Configuration

The system uses a JSON-based configuration file. Generate a default configuration:

```bash
python3 cli.py save-config
```

### Configuration Options

```json
{
    "network": {
        "interface": "any",
        "promiscuous_mode": true,
        "packet_count": 0,
        "timeout": 10
    },
    "detection": {
        "port_scan": {
            "enabled": true,
            "threshold": 10,
            "time_window": 60
        },
        "brute_force": {
            "enabled": true,
            "threshold": 5,
            "time_window": 300
        },
        "malformed_packet": {
            "enabled": true,
            "check_tcp_flags": true
        },
        "dos_attack": {
            "enabled": true,
            "threshold": 100,
            "time_window": 10
        }
    },
    "logging": {
        "database": "intrusion_detection.db",
        "log_file": "ids.log",
        "console_output": true
    }
}
```

## Testing

### Run Unit Tests

```bash
python3 tests/test_detector.py
```

### Run Attack Simulations

The testing module includes interactive attack simulations (requires root privileges):

```bash
sudo python3 tests/test_detector.py --manual
```

Available simulations:
1. Port Scan Simulation
2. Brute Force Simulation
3. Malformed Packets Simulation
4. DoS Attack Simulation

## Architecture

```
Real-Time-Network-Intrusion-Detection-System/
├── cli.py                    # Command-line interface
├── requirements.txt          # Python dependencies
├── README.md                # Documentation
├── src/                     # Source code modules
│   ├── __init__.py         # Package initialization
│   ├── config.py           # Configuration management
│   ├── database.py         # Database operations
│   ├── alert_logger.py     # Alert logging and notifications
│   └── detector.py         # Main detection engine
└── tests/                   # Testing modules
    └── test_detector.py    # Unit tests and simulations
```

## Alert Types and Severity Levels

### Alert Types
- `port_scan`: Port scanning activity detected
- `brute_force`: Brute force authentication attempts
- `malformed_packet`: Malformed or suspicious packets
- `dos_attack`: Denial of Service attack patterns

### Severity Levels
- `CRITICAL`: Immediate action required (e.g., brute force, DoS)
- `HIGH`: Significant threat detected (e.g., port scan)
- `MEDIUM`: Suspicious activity (e.g., malformed packets)
- `LOW`: Minor anomalies

## Database Schema

### Alerts Table
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
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
```

## Requirements

- **scapy**: Packet capture and manipulation library (>=2.5.0)

## Limitations and Notes

1. **Requires Root Privileges**: Packet capture requires elevated privileges to access network interfaces
2. **Network Interface**: The system can monitor all interfaces (`any`) or specific interfaces
3. **Performance**: High-traffic networks may require tuning of detection thresholds
4. **False Positives**: Tune configuration parameters to reduce false positives in your environment

## Security Considerations

- Run the IDS on a dedicated monitoring interface when possible
- Regularly review and tune detection rules to match your environment
- Keep the database secure as it contains network traffic information
- Monitor system resources when running on high-traffic networks

## Troubleshooting

### "Scapy not available" error
Install Scapy:
```bash
pip install scapy
```

### Permission denied errors
Run with sudo/administrator privileges:
```bash
sudo python3 cli.py start
```

### No packets captured
- Check network interface selection
- Verify network activity on the selected interface
- Ensure promiscuous mode is supported

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is open source and available for educational and research purposes.

## Acknowledgments

Built with:
- [Scapy](https://scapy.net/) - Packet manipulation library
- Python standard library
- SQLite database

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/chandana410/Real-Time-Network-Intrusion-Detection-System).

---

**Warning**: This tool is for educational and authorized security testing purposes only. Unauthorized use of this tool to monitor or attack networks you don't own or have permission to test is illegal.
