# ProXDefend - Advanced System Security Monitor

## Overview
ProXDefend is a comprehensive system security monitoring application that provides real-time monitoring of processes, network connections, and system activities. It helps identify potential security threats and provides tools for system administrators to maintain system integrity.

## Key Features

### 1. Process Monitoring
- Real-time process tracking and analysis
- Detection of suspicious process behaviors
- Process crash monitoring
- Memory usage analysis
- Process anomaly detection

### 2. Network Security
- Active network connection monitoring
- Traffic analysis and anomaly detection
- Connection classification (suspicious vs. legitimate)
- Network interface monitoring
- Socket change tracking
- Speed testing and network diagnostics

### 3. File System Security
- File scanning and analysis
- Entropy calculation for detecting encrypted/compressed files
- File structure analysis
- Directory change monitoring
- System integrity checking

### 4. System Health Monitoring
- System uptime tracking
- Memory analysis
- Startup location monitoring
- System log analysis
- Health metrics collection

## Technical Components

### Core Libraries Used
- `Flask`: Web framework for the application interface
- `psutil`: Process and system monitoring
- `scapy`: Network packet analysis
- `yara`: Pattern matching for malware detection
- `reportlab`: PDF report generation
- `python-dotenv`: Environment variable management
- `requests`: HTTP requests for API calls
- `PyPDF2`: PDF manipulation
- `python-docx`: Document handling

### Key Functions

#### Process Management
- `get_processes()`: Retrieves system processes
- `detect_process_anomalies()`: Identifies suspicious process behaviors
- `track_process_crashes()`: Monitors process stability

#### Network Security
- `get_network_connections()`: Lists active network connections
- `analyze_network_traffic()`: Analyzes network patterns
- `detect_traffic_anomalies()`: Identifies unusual network activity
- `get_network_interfaces()`: Monitors network interfaces

#### File System
- `scan_file_basic()`: Basic file scanning
- `scan_file_enhanced()`: Advanced file analysis
- `calculate_entropy()`: Detects encrypted/compressed files
- `track_directory_changes()`: Monitors file system changes

#### System Health
- `check_system_integrity()`: Verifies system file integrity
- `analyze_system_logs()`: Processes system logs
- `get_system_health()`: Collects system health metrics

## Security Features

### Process Protection
- Real-time monitoring of process creation and termination
- Detection of suspicious process behaviors
- Memory usage analysis for potential threats
- Process crash monitoring for system stability

### Network Protection
- Active connection monitoring
- Traffic pattern analysis
- Suspicious connection detection
- Network interface security
- Socket change tracking

### File System Protection
- File integrity monitoring
- Suspicious file detection
- Directory change tracking
- System file protection

## Usage

### Installation
1. Clone the repository
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up environment variables in `.env` file
4. Run the application:
   ```bash
   python main.py
   ```

### Accessing the Interface
- Main dashboard: `http://localhost:5000`
- Process monitor: `http://localhost:5000/processes`
- Network monitor: `http://localhost:5000/network`
- File scanner: `http://localhost:5000/scanner`

## Security Considerations

### System Requirements
- Windows 10 or later
- Administrator privileges for full functionality
- Python 3.8 or later
- Sufficient system resources for monitoring

### Best Practices
1. Run with administrator privileges for full functionality
2. Regular updates of the application
3. Monitor system resources
4. Regular review of security logs
5. Keep dependencies updated

## Contributer
Sanika Pokharkar