# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZeroDayBuddy is a comprehensive bug bounty assistant tool written in Go that streamlines security research workflows. It integrates with bug bounty platforms (HackerOne, Bugcrowd) and provides automated reconnaissance, vulnerability scanning, and reporting capabilities.

## Architecture

The codebase follows a clean architecture pattern:

- **cmd/zerodaybuddy/**: CLI entry point using Cobra framework
- **internal/core/**: Core application logic, orchestrates services via the `App` struct
- **internal/platform/**: Bug bounty platform integrations (HackerOne, Bugcrowd)
- **internal/recon/**: Reconnaissance service with multiple scanner integrations
- **internal/scan/**: Vulnerability scanning service (currently stub implementation)
- **internal/report/**: Report generation for findings and projects
- **internal/storage/**: SQLite database layer with Store interface
- **internal/web/**: HTTP server for web UI (port 8080)
- **pkg/**: Shared packages (config, models, utils)

## Key Interfaces

- **Scanner**: Interface for all reconnaissance tools (internal/recon/scanner.go)
- **Platform**: Interface for bug bounty platforms (internal/platform/platform.go)
- **Store**: Interface for data persistence (internal/storage/store.go)

## Integrated Security Tools

The recon service integrates these external tools:
- Subfinder, Amass (subdomain enumeration)
- HTTPX (HTTP probing)
- Naabu (port scanning)
- Katana (web crawling)
- Wayback (historical URLs)
- FFUF (content discovery)
- Nuclei (vulnerability scanning)

## Development Commands

Build the project:
```bash
go build -o zerodaybuddy ./cmd/zerodaybuddy
```

Run the application:
```bash
./zerodaybuddy [command]
```

Available commands: init, list-programs, project, recon, scan, report, serve

## Configuration

- Config file: `~/.zerodaybuddy/config.yaml`
- Environment variables: `BUGBASE_` prefix
- Database: SQLite at `~/.zerodaybuddy/zerodaybuddy.db`

## Current Issues

1. **Compilation Error**: The `SQLiteStore` struct doesn't implement all methods of the `Store` interface. Missing implementations need to be added.
2. **No Tests**: The project currently has no test files.
3. **Stub Implementation**: The scan service is only a stub and needs implementation.

## Important Notes

- Always validate target scope before running scans
- The web server runs on port 8080 by default
- JSON fields in the database use custom serialization (see pkg/utils/json.go)
- Rate limiting is implemented for external API calls
- Follow ethical guidelines when using reconnaissance features