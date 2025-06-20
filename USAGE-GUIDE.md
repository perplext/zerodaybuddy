# ZeroDayBuddy Usage Guide

This document provides detailed instructions on how to use ZeroDayBuddy for bug bounty and security assessment projects.

## Table of Contents

- [Getting Started](#getting-started)
- [Project Management](#project-management)
- [Reconnaissance](#reconnaissance)
- [Scanning](#scanning)
- [Report Generation](#report-generation)
- [Web Interface](#web-interface)
- [Ethical Guidelines](#ethical-guidelines)
- [Troubleshooting](#troubleshooting)

## Getting Started

### Installation

**Option 1: Download Pre-built Binary (Recommended)**

Download the latest release for your platform from the [GitHub Releases](https://github.com/perplext/zerodaybuddy/releases) page:

```bash
# Linux (x64)
curl -L -o zerodaybuddy https://github.com/perplext/zerodaybuddy/releases/latest/download/zerodaybuddy-linux-amd64
chmod +x zerodaybuddy
sudo mv zerodaybuddy /usr/local/bin/

# macOS (Apple Silicon)  
curl -L -o zerodaybuddy https://github.com/perplext/zerodaybuddy/releases/latest/download/zerodaybuddy-darwin-arm64
chmod +x zerodaybuddy
sudo mv zerodaybuddy /usr/local/bin/

# macOS (Intel)
curl -L -o zerodaybuddy https://github.com/perplext/zerodaybuddy/releases/latest/download/zerodaybuddy-darwin-amd64
chmod +x zerodaybuddy
sudo mv zerodaybuddy /usr/local/bin/
```

**Option 2: Build from Source**

```bash
# Clone the repository
git clone https://github.com/perplext/zerodaybuddy.git
cd zerodaybuddy

# Build the tool
go build -o zerodaybuddy ./cmd/zerodaybuddy

# Install to your path (optional)
sudo mv zerodaybuddy /usr/local/bin/
```

### Initial Configuration

Before using ZeroDayBuddy, you need to initialize the configuration:

```bash
# Initialize with default settings
zerodaybuddy init

# Or specify a custom config location
zerodaybuddy init --config /path/to/config.yaml
```

The initialization process will:
1. Create a default configuration file
2. Set up the database
3. Configure default workspace directories

## Project Management

### Creating a New Project

```bash
# Create a project from a bug bounty platform
zerodaybuddy project create --platform hackerone --program example-program
```

### Listing Projects

```bash
# List all projects
zerodaybuddy project list
```

### Managing Project Scope

Project scope is automatically configured when creating projects from bug bounty platforms. Manual scope management commands are planned for future releases.

## Reconnaissance

### Running Reconnaissance

```bash
# Run full reconnaissance on a project
zerodaybuddy recon run --project example-program

# Control concurrency
zerodaybuddy recon run --project example-program --concurrent 5
```

### Viewing Reconnaissance Results

Use the web interface (`zerodaybuddy serve`) to view reconnaissance results, or check the SQLite database directly. Command-line result viewing is planned for future releases.

## Scanning

### Running Vulnerability Scans

```bash
# Run all scanners on a project
zerodaybuddy scan run --project example-program

# Scan specific target
zerodaybuddy scan run --project example-program --target "https://api.example.com"

# Control concurrency
zerodaybuddy scan run --project example-program --concurrent 3
```

### Managing Findings

Use the web interface (`zerodaybuddy serve`) to view and manage findings. Command-line finding management is planned for future releases.

## Report Generation

ZeroDayBuddy provides comprehensive report generation capabilities for both project-wide and finding-specific reports.

### Generating Project Reports

```bash
# Generate a project report (markdown format, default)
zerodaybuddy report generate --project example-program

# Generate PDF report
zerodaybuddy report generate --project example-program --format pdf

# Specify output file
zerodaybuddy report generate --project example-program --format pdf --output report.pdf
```

### Generating Finding Reports

```bash
# Generate a report for a specific finding
zerodaybuddy report generate --project example-program --finding "f8d2e3a1-b6c7-4e5d-9f0a-1b2c3d4e5f6a" --format pdf
```

### Report Formats

ZeroDayBuddy supports multiple report formats:
- `markdown`: Markdown format for easy version control and editing (default)
- `pdf`: Professional PDF reports suitable for client delivery

## Web Interface

ZeroDayBuddy includes a web interface for easier management and visualization.

### Starting the Web Server

```bash
# Start the web server on default port (8080)
zerodaybuddy serve

# Specify a custom port
zerodaybuddy serve --port 9000

# Bind to specific host
zerodaybuddy serve --host 127.0.0.1 --port 9000
```

### Web Interface Features

The web interface provides:
- Dashboard with project overview
- Interactive reconnaissance results
- Visual representation of attack surface
- Finding management
- Report generation and customization
- Real-time scan monitoring

## Ethical Guidelines

ZeroDayBuddy is designed for legitimate security testing. Users must adhere to the following ethical guidelines:

1. **Only scan systems you own or have explicit permission to test**
2. **Respect the scope defined in bug bounty programs**
3. **Do not use ZeroDayBuddy for illegal activities or unauthorized testing**
4. **Follow responsible disclosure practices**
5. **Respect rate limits and avoid causing service disruption**

Failure to follow these guidelines could result in legal consequences and damage to the security community's reputation.

## Troubleshooting

### Common Issues

#### Database Connection Problems

```bash
# Run database migrations if needed
zerodaybuddy migrate up
```

#### Scan Failures

If scans are failing, check:
1. Network connectivity to targets
2. Proper scope configuration
3. Firewall or proxy settings
4. Logs at `~/.zerodaybuddy/logs/`

#### Permission Issues

Check file permissions for the config directory (`~/.zerodaybuddy/`) and database file.

### Getting Help

```bash
# Show help for any command
zerodaybuddy --help
zerodaybuddy [command] --help

# Show version information
zerodaybuddy version
```

For more detailed assistance, refer to the documentation in the `docs/` directory or open an issue on GitHub.
