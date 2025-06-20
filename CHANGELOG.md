# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-06-19

### Added
- **Core CLI Framework**: Complete command-line interface with Cobra
  - `init` - Initialize ZeroDayBuddy configuration
  - `list-programs` - List available bug bounty programs  
  - `project` - Manage bug bounty projects
  - `recon` - Manage reconnaissance tasks
  - `scan` - Manage vulnerability scanning tasks
  - `report` - Manage vulnerability reports
  - `serve` - Start the web server
  - `version` - Display version information

- **Platform Integrations**: 
  - HackerOne API integration
  - Bugcrowd API integration
  - Program discovery and scope management

- **Reconnaissance Engine**:
  - Subdomain enumeration (Subfinder, Amass)
  - HTTP probing (HTTPX)
  - Port scanning (Naabu)
  - Web crawling (Katana)
  - Historical URL discovery (Wayback)
  - Content discovery (FFUF)
  - Vulnerability scanning (Nuclei)

- **Web Interface**:
  - Dashboard for project management
  - Real-time scan monitoring
  - Interactive results exploration
  - Report generation interface

- **Security Features**:
  - JWT-based authentication
  - Secure password hashing (bcrypt)
  - Rate limiting for API calls
  - Secure logging with sensitive data masking
  - Scope validation for all targets

- **Data Management**:
  - SQLite database with migration system
  - Comprehensive data models for projects, hosts, endpoints, findings
  - Export capabilities (JSON, CSV, PDF reports)

- **Testing & Quality**:
  - Comprehensive test suite (35+ test files)
  - Integration test support with build tags
  - Security vulnerability scanning
  - GitHub Actions CI/CD pipeline

### Security
- Fixed clear-text password logging vulnerabilities (CWE-312)
- Implemented proper workflow permissions (CWE-275)
- Added secure logging methods with automatic sensitive data masking
- Ensured password fields are never serialized in responses

### Infrastructure
- Multi-platform release builds (Linux, macOS, Windows)
- Automated GitHub Actions workflows for CI and releases
- Docker support for containerized deployments
- Comprehensive documentation and usage guides

[Unreleased]: https://github.com/perplext/zerodaybuddy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/perplext/zerodaybuddy/releases/tag/v0.1.0