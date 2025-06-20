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
# Create a project manually
zerodaybuddy project create --name "Example Project" --scope "example.com,*.example.com"

# Create a project from a bug bounty platform
zerodaybuddy project create --platform hackerone --program example-program
```

### Listing Projects

```bash
# List all projects
zerodaybuddy project list

# Show detailed information about a specific project
zerodaybuddy project info --name "Example Project"
```

### Managing Project Scope

```bash
# Add domains to scope
zerodaybuddy project scope add --name "Example Project" --domains "api.example.com,admin.example.com"

# Remove domains from scope
zerodaybuddy project scope remove --name "Example Project" --domains "test.example.com"

# Import scope from file
zerodaybuddy project scope import --name "Example Project" --file scope.txt
```

## Reconnaissance

### Running Reconnaissance

```bash
# Run full reconnaissance on a project
zerodaybuddy recon run --project "Example Project"

# Run specific recon modules
zerodaybuddy recon run --project "Example Project" --modules subdomain,port-scan

# Resume a previous recon session
zerodaybuddy recon resume --project "Example Project" --session 12345
```

### Viewing Reconnaissance Results

```bash
# List discovered hosts
zerodaybuddy recon hosts --project "Example Project"

# List discovered endpoints
zerodaybuddy recon endpoints --project "Example Project" --host "api.example.com"

# Export recon results
zerodaybuddy recon export --project "Example Project" --format json --output recon-results.json
```

## Scanning

### Running Vulnerability Scans

```bash
# Run all scanners on a project
zerodaybuddy scan run --project "Example Project"

# Run specific scanners
zerodaybuddy scan run --project "Example Project" --scanners xss,sqli,ssrf

# Scan specific targets
zerodaybuddy scan run --project "Example Project" --targets "api.example.com:443"
```

### Managing Findings

```bash
# List all findings
zerodaybuddy finding list --project "Example Project"

# Show details of a specific finding
zerodaybuddy finding info --id "f8d2e3a1-b6c7-4e5d-9f0a-1b2c3d4e5f6a"

# Update a finding
zerodaybuddy finding update --id "f8d2e3a1-b6c7-4e5d-9f0a-1b2c3d4e5f6a" --status confirmed
```

## Report Generation

ZeroDayBuddy provides comprehensive report generation capabilities for both project-wide and finding-specific reports.

### Generating Project Reports

```bash
# Generate a project report
zerodaybuddy report generate --project "Example Project" --format pdf

# Specify output file
zerodaybuddy report generate --project "Example Project" --format pdf --output "/path/to/report.pdf"

# Include additional metadata
zerodaybuddy report generate --project "Example Project" --format pdf --include-metadata
```

### Generating Finding Reports

```bash
# Generate a report for a specific finding
zerodaybuddy report generate --finding "f8d2e3a1-b6c7-4e5d-9f0a-1b2c3d4e5f6a" --format pdf

# Customize finding report
zerodaybuddy report generate --finding "f8d2e3a1-b6c7-4e5d-9f0a-1b2c3d4e5f6a" --format pdf --template "detailed"
```

### Report Formats

ZeroDayBuddy supports multiple report formats:
- `pdf`: Professional PDF reports suitable for client delivery
- `md`: Markdown format for easy version control and editing
- `html`: HTML reports for web viewing
- `json`: JSON format for programmatic processing

### Report Templates

Several report templates are available:
- `standard`: A balanced report with all essential information
- `detailed`: Comprehensive report with extensive technical details
- `executive`: Executive summary focused on business impact
- `submission`: Formatted specifically for bug bounty platform submission

## Web Interface

ZeroDayBuddy includes a web interface for easier management and visualization.

### Starting the Web Server

```bash
# Start the web server on default port (8080)
zerodaybuddy serve

# Specify a custom port
zerodaybuddy serve --port 9000

# Bind to specific address
zerodaybuddy serve --address 127.0.0.1 --port 9000
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
# Verify database integrity
zerodaybuddy db check

# Repair database
zerodaybuddy db repair
```

#### Scan Failures

If scans are failing, check:
1. Network connectivity to targets
2. Proper scope configuration
3. Firewall or proxy settings
4. Logs at `~/.zerodaybuddy/logs/`

#### Permission Issues

```bash
# Check for permission issues
zerodaybuddy doctor

# Fix permissions
zerodaybuddy doctor --fix
```

### Getting Help

```bash
# Show help for any command
zerodaybuddy --help
zerodaybuddy [command] --help

# Show version information
zerodaybuddy version
```

For more detailed assistance, refer to the documentation in the `docs/` directory or open an issue on GitHub.
