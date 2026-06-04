# CLAUDE.md

## MANDATORY: Use td for Task Management

You must run td usage --new-session at conversation start (or after /clear) to see current work.
Use td usage -q for subsequent reads.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Active priorities and prioritized backlog:** see `docs/brainstorms/codebase-punch-list-requirements.md`. That document is the canonical source for what's next, organized by tier (correctness → hygiene → leverage → expansion → polish).

## Project Overview

ZeroDayBuddy is a comprehensive bug bounty assistant tool written in Go that streamlines security research workflows. It integrates with bug bounty platforms (HackerOne, Bugcrowd, Immunefi) and provides automated reconnaissance, vulnerability scanning, and reporting capabilities.

## Architecture

The codebase follows a clean architecture pattern:

- **cmd/zerodaybuddy/**: CLI entry point using Cobra framework
- **cmd/hashpass/**: Standalone bcrypt password hashing utility
- **internal/core/**: Core application logic, orchestrates services via the `App` struct
- **internal/platform/**: Bug bounty platform integrations (HackerOne, Bugcrowd, Immunefi)
- **internal/recon/**: Reconnaissance service with multiple scanner integrations
- **internal/scan/**: Vulnerability scanning service — Nuclei orchestration with SSRF filtering, semaphore concurrency, and finding ingest
- **internal/report/**: Report generation — Markdown, JSON, CSV, SARIF v2.1.0, and GitHub issue integration
- **internal/storage/**: SQLite database layer with Store interface and bulk operations
- **internal/auth/**: bcrypt password hashing, JWT issuance with auto-generated secret, refresh tokens
- **internal/web/**: HTTP server scaffold (see "Web UI Status" below)
- **pkg/**: Shared packages (config, models, utils, errors, validation, ratelimit)

## Web UI Status

> **The web UI is built but not yet wired.** `internal/web/handlers/` (auth) and `internal/web/middleware/` (auth, errors, ratelimit, security) contain implemented, tested code, but `internal/web/server.go` currently registers only `/health` and a static welcome page. Wiring is tracked as Tier 2 work in the punch list (`docs/brainstorms/codebase-punch-list-requirements.md`). When working in `internal/web/`, do not assume the handler/middleware code is reachable from the running server.

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
- Gitleaks (secrets scanning)
- Trivy (vulnerability and container scanning)

## Report Capabilities

- **Markdown / JSON / CSV**: Standard report formats for findings and project summaries
- **SARIF v2.1.0**: GitHub-uploadable static analysis report (`internal/report/sarif.go`)
- **GitHub Issues**: Automatic issue creation from findings via the GitHub API (`internal/report/github.go`)

## Development Commands

Build the project:
```bash
go build -o zerodaybuddy ./cmd/zerodaybuddy
```

Run the application:
```bash
./zerodaybuddy [command]
```

Available commands: init, list-programs, project, recon, scan, report, serve, version, migrate

### Manual project mode

Projects can be created without a bug-bounty platform API, from a hand-authored
scope file (for individual hackers, pentests, or arbitrary research):

```bash
zerodaybuddy project create --manual --name my-target --scope-file scope.yaml
```

The scope file is YAML or JSON with `in_scope[]` / `out_of_scope[]` arrays; each
asset's `type` must be one of the `models.AssetType` values (domain, ip, url,
mobile, binary, container, smart_contract, repository, other). Wildcards
(`*.example.com`) and CIDR ranges (`10.0.0.0/8`) live in the asset `value`, not a
separate type. See `examples/scope.yaml`. Loading/validation lives in
`pkg/models/scopefile.go` (`LoadScopeFile` / `ValidateScope`), shared by the CLI
and the web `POST /api/projects` handler via `models.NewManualProject`. Manual
mode requires a non-empty `in_scope`. Internal/RFC-1918 ranges are allowed in
scope; the scan service's SSRF filter remains the enforcement boundary for what
is actually reachable.

## Configuration

- Config file: `~/.zerodaybuddy/config.yaml`
- Environment variables: `BUGBASE_` prefix
- Database: SQLite at `~/.zerodaybuddy/zerodaybuddy.db`

## Project Status

**Build Status**: ✅ Compiles successfully
**Test Coverage**: ✅ 53+ test files; all 20 packages green
**Core Implementation**: ✅ Storage, scanning, recon, auth, and reports are real implementations (not stubs)

### Test Execution

**Unit Tests**: Run without external dependencies
```bash
go test ./... -short
```

**Integration Tests**: Require external security tools (amass, naabu, nuclei, gitleaks, trivy)
```bash
go test ./... -tags=integration
```

## Important Notes

- Always validate target scope before running scans (use `pkg/models.Scope.IsInScope` — wildcards, CIDR, and dot-anchored subdomain matching all supported)
- The web server runs on port 8080 by default (currently serves only `/health` and welcome page — see "Web UI Status" above)
- JSON fields in the database use custom serialization (see pkg/utils/json.go)
- Rate limiting is implemented for external API calls (`pkg/ratelimit/`)
- SSRF protection in the scan service blocks RFC 1918, cloud metadata, and IPv6 ULA/link-local ranges
- JWT secret is auto-generated on first run if not configured (32-byte hex)
- Follow ethical guidelines when using reconnaissance features
