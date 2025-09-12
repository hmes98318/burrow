# malicious-detector

<img width="150" height="150" align="right" style="float: right; margin: 0 10px 0 0;" alt="malicious-detector-logo" src="public/img/logo.svg">


[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg?style=for-the-badge)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

A comprehensive malicious IP threat intelligence system that monitors log files for suspicious activities and maintains a centralized threat intelligence database. The system consists of two main components: **Detector** (log monitoring agents) and **Panel** (central management platform).


## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Detector 1   │    │    Detector 2   │    │    Detector N   │
│  (Log Monitor)  │    │  (Log Monitor)  │    │  (Log Monitor)  │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                   ┌─────────────▼───────────────┐
                   │         Panel Server        │
                   │   (Threat Intelligence)     │
                   │                             │
                   │  ┌─────────┐ ┌───────────┐  │
                   │  │   API   │ │    Web    │  │
                   │  │ Server  │ │ Dashboard │  │
                   │  └─────────┘ └───────────┘  │
                   │                             │
                   │      ┌─────────────┐        │
                   │      │  SQLite DB  │        │
                   │      └─────────────┘        │
                   └─────────────────────────────┘
                                 │
              ┌──────────────────┼─────────────────┐
              │                  │                 │
    ┌─────────▼────────┐  ┌──────▼──────┐ ┌────────▼────────┐
    │    FortiGate     │  │ Palo Alto   │ │    pfSense      │
    │   Integration    │  │ Integration │ │  Integration    │
    └──────────────────┘  └─────────────┘ └─────────────────┘
```


## ✨ Features

### 🔍 **Detector (Log Monitoring Agent)**
- **Real-time Log Monitoring**: Continuously monitors multiple log files
- **Advanced Pattern Matching**: Uses configurable regex patterns with placeholder support
- **Multi-service Support**: SSH, Nginx, Apache, FTP, Nextcloud, and more
- **Performance Optimized**: Efficient regex detection
- **Centralized Reporting**: Automatically reports threats to Panel server

### 🎛️ **Panel (Central Management Platform)**
- **Threat Intelligence Database**: Centralized storage of malicious IP data
- **Multi-detector Management**: Supports unlimited detector agents
- **RESTful API**: Complete API for integration and automation
- **Web Dashboard**: Real-time monitoring and management interface (UNDER DEVELOPMENT)
- **Firewall Integration**: Direct export formats for major firewall vendors
- **Heartbeat Monitoring**: Real-time detector health monitoring
- **CIDR Block Support**: Optional /24 CIDR aggregation for efficient blocking

### 🔥 **Firewall Integration**
- **FortiGate**: External Connectors support (131k/300k IP limits)
- **Palo Alto**: External dynamic list format
- **pfSense**: IP list format for aliases
- **Nginx**: Geo module integration with automatic updates
- **Custom Formats**: Extensible for additional firewall vendors


## 🚀 Quick Start

### Prerequisites
- Go 1.24 or later
- SQLite3 (for Panel database)
- Linux/Unix system (for log file monitoring)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/hmes98318/malicious-detector.git
cd malicious-detector
```

2. **Build the system**
```bash
make build
```

3. **Install binaries (optional)**
```bash
# Install both components
make install

# Or install components separately:
make install-panel         # Install only Panel server
make install-detector      # Install only Detector agent
```

#### Component-specific Installation

For distributed deployments, you can install components on different servers:

**Panel Server Installation:**
```bash
# On the central management server
make install-panel
```

**Detector Agent Installation:**
```bash
# On each monitoring server
make install-detector
```

### Setup Panel Server

1. **Start the Panel**
```bash
./bin/panel -port 8080 -db ./panel.db
# or
./bin/panel -config ./panel.ymal
```

2. **Create a detector token**
```bash
curl -X POST http://localhost:8080/api/v1/detectors \
  -H "Content-Type: application/json" \
  -d '{"name": "my-detector"}'
```

The response will include a token for your detector.

### Setup Detector Agent

1. **Create detector configuration**
```bash
./bin/detector -create-sample -config detector.yaml
```

2. **Edit the configuration**
```yaml
panel_url: "http://your-panel-server:8080"
token: "your-detector-token-here"
name: "detector-1"
include_private_ips: false
heartbeat_interval: 10

# Placeholders for regex patterns
placeholders:
  ip_regex: '((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})'
  http_method_regex: '(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)'

logs:
  - description: "SSH brute force detection"
    path: "/var/log/auth.log"
    regex: 'Failed password for .+ from {{ ip_regex }}'
    max_retry: 5
    time_window: 10
    scan_interval: 1000
```

3. **Start the detector**
```bash
./bin/detector -config detector.yaml
```


## 📊 Supported Log Types

The system includes pre-configured patterns for:

| Service | Description | Detection Pattern |
|---------|-------------|-------------------|
| **SSH** | Brute force attacks | Failed password attempts |
| **Nginx** | Vulnerability scans | Requests for sensitive files (.env, .git, admin panels) |
| **Apache** | Web attacks | Access to .htaccess, config files |
| **FTP** | Login failures | Failed FTP authentication |
| **Nextcloud** | Brute force | Failed login attempts |


## 🔧 Configuration

### Placeholder System

The configuration uses a powerful placeholder system to reduce redundancy:

```yaml
placeholders:
  ip_regex: '((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})'
  
logs:
  - regex: 'Failed login from {{ ip_regex }}'  # Automatically replaced
```

### Advanced Configuration Options

```yaml
# Panel Configuration
panel_url: "http://panel-server:8080"
token: "detector-token"
name: "detector-name"
include_private_ips: false    # Include private IP ranges
heartbeat_interval: 10        # Heartbeat frequency (seconds)

# Log Monitoring
logs:
  - description: "Service description"
    path: "/path/to/log/file"
    regex: 'pattern to match'
    max_retry: 5              # Threshold for marking as malicious
    time_window: 10           # Time window in minutes
    scan_interval: 1000       # Scan frequency in milliseconds
```


## 🌐 API Reference

### Detector Management
```bash
# Create detector
POST /api/v1/detectors
{"name": "detector-name"}

# List detectors
GET /api/v1/detectors

# Get detector details
GET /api/v1/detectors/{id}
```

### Threat Intelligence
```bash
# Report malicious IP
POST /api/v1/report
{
  "detector_id": "token",
  "ip": "192.168.1.100",
  "reason": "SSH brute force",
  "log_path": "/var/log/auth.log",
  "count": 5
}

# Get malicious IPs
GET /api/v1/malicious-ips

# Get firewall-specific format
GET /malicious-ips/fortigate-13k-1.txt    # FortiOS <= 7.4.4 (max 131,072 IPs per list)
GET /malicious-ips/fortigate-30k-1.txt    # FortiOS > 7.4.4 (max 300,000 IPs per list)
GET /malicious-ips/palo-alto-1.txt
GET /malicious-ips/pfsense-1.txt
GET /malicious-ips/nginx-geo-1.txt         # Nginx Geo module format
GET /malicious-ips/iptables-1.txt          # iptables format
GET /malicious-ips/opnsense-1.txt          # OPNsense format
```


## 🔥 Firewall Integration

### FortiGate

#### External Connectors (FortiOS 6.2+)
```bash
# For FortiOS <= 7.4.4 (max 131,072 IPs per list)
config system external-resource
    edit "malicious-ips-13k"
        set type address
        set refresh-rate 1    # 1 minute (1 - 43200)
        set resource "https://your-panel-server:8080/malicious-ips/fortigate-13k-1.txt"
        set comment "Malicious IP Threat Intelligence - Standard Format"
    next
end

# For FortiOS > 7.4.4 (max 300,000 IPs per list)
config system external-resource
    edit "malicious-ips-30k"
        set type address
        set refresh-rate 1    # 1 minute (1 - 43200)
        set resource "https://your-panel-server:8080/malicious-ips/fortigate-30k-1.txt"
        set comment "Malicious IP Threat Intelligence - Extended Format"
    next
end

# Apply to firewall policy
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set internet-service-name "malicious-ips-13k"  # or "malicious-ips-30k"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
```

**Note**: FortiOS versions prior to 6.2 do not support External Connectors. For older versions, manual IP address object creation or upgrade to a supported FortiOS version is required.

### Palo Alto Networks
```bash
# Configure external dynamic list
set shared external-list malicious-ips type ip recurring hourly url http://your-panel-server:8080/malicious-ips/palo-alto-1.txt
```

### pfSense
```bash
# Create alias with URL table
Firewall > Aliases > URLs
Name: MaliciousIPs
URL: http://your-panel-server:8080/malicious-ips/pfsense-1.txt
Update Frequency: 1 hour
```

### Nginx Reverse Proxy / Web Server

#### Method 1: Direct Geo Module Configuration
```nginx
# In nginx.conf or server block
geo $malicious_ip_blocked {
    default 0;
    include conf.d/list/malicious-ips.list;
}

server {
    # Block malicious IPs
    if ($malicious_ip_blocked = 1) {
        return 403;  # or 404 for stealth mode
    }

    # Your server configuration...
}
```

#### Method 2: Automated Download and Include
Create update script: `/etc/nginx/scripts/update-malicious-ips.sh`  
```bash
#!/bin/bash
export PATH=/sbin:/usr/sbin:/usr/bin:/bin

NGINX_CONF_DIR="/etc/nginx/conf.d"
PANEL_URL="http://your-panel-server:8080"
TARGET_FILE="${NGINX_CONF_DIR}/list/malicious-ips.list"
TEMP_FILE="${TARGET_FILE}.tmp"

# Create directory if it doesn't exist
mkdir -p "$(dirname "$TARGET_FILE")"

# Download malicious IP list to temporary file
if curl -s "${PANEL_URL}/malicious-ips/nginx-geo-1.txt" > "$TEMP_FILE"; then
    # Check if target file exists
    if [ ! -f "$TARGET_FILE" ]; then
        # First run - target file doesn't exist
        mv "$TEMP_FILE" "$TARGET_FILE"
        echo "$(date): First run - Malicious IP list created, reloading nginx..."
        
        # Test and reload nginx configuration
        if nginx -t; then
            nginx -s reload
            echo "$(date): Nginx reloaded successfully"
        else
            echo "$(date): Nginx configuration test failed, removing invalid file"
            rm -f "$TARGET_FILE"
        fi
    elif ! cmp -s "$TARGET_FILE" "$TEMP_FILE"; then
        # Files are different, backup old file and update
        cp "$TARGET_FILE" "${TARGET_FILE}.backup"
        mv "$TEMP_FILE" "$TARGET_FILE"
        echo "$(date): Malicious IP list updated, reloading nginx..."
        
        # Test and reload nginx configuration
        if nginx -t; then
            nginx -s reload
            echo "$(date): Nginx reloaded successfully"
            # Remove backup file after successful reload
            rm -f "${TARGET_FILE}.backup"
        else
            echo "$(date): Nginx configuration test failed, restoring old file"
            # Restore old file if nginx test fails
            mv "${TARGET_FILE}.backup" "$TARGET_FILE"
        fi
    else
        # Files are identical, no need to reload
        rm "$TEMP_FILE"
        echo "$(date): Malicious IP list unchanged, skipping reload"
    fi
else
    echo "$(date): Failed to download malicious IP list"
    rm -f "$TEMP_FILE"
    exit 1
fi

# Add to crontab for automatic updates
# */5 * * * * /etc/nginx/scripts/update-malicious-ips.sh >> /var/log/nginx/malicious-ips-update.log 2>&1
```


## 🧪 Testing

### Run All Tests
```bash
make test
```

### Specific Test Categories
```bash
# Test log regex patterns
go test -v ./test/ -run TestLogRegexes

# Test placeholder functionality
go test -v ./test/ -run TestProcessPlaceholders

# Performance benchmarks
go test -bench=. ./test/
```


## 📈 Monitoring & Statistics

The detector provides comprehensive statistics:

```bash
# Enable debug mode for detailed statistics
./bin/detector -config detector.yaml -debug
```

Statistics include:
- Total scans performed
- Lines processed
- Average scan time
- Currently tracked IPs
- Scan intervals and performance metrics


## 🛠️ Development

### Project Structure
```
malicious-detector/
├── cmd/                    # Main applications
│   ├── detector/          # Detector agent
│   └── panel/             # Panel server
├── internal/              # Internal packages
│   ├── detector/          # Detector logic
│   ├── panel/             # Panel logic
│   └── shared/            # Shared types and utilities
├── configs/               # Configuration files
├── test/                  # Test files
├── web/                   # Web dashboard
└── Makefile              # Build automation
```

### Build Targets
```bash
make build                 # Build all binaries
make panel                 # Build only panel
make detector              # Build only detector
make test                  # Run tests
make clean                 # Clean build artifacts
make install               # Install both binaries to system
make install-panel         # Install only panel binary to system
make install-detector      # Install only detector binary to system
```


## 📋 Requirements

### System Requirements
- **OS**: Linux, macOS
- **Memory**: Minimum 512MB RAM
- **Network**: HTTP/HTTPS connectivity for Panel communication

### Development Environment
This project is being developed and tested on:
- **Rocky Linux 9.6**
- **Ubuntu 24.04 LTS**

Other Linux distributions should work but may require additional testing.

### Dependencies
- Go 1.24+ (for building)
- SQLite3 (embedded, no separate installation required)


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
