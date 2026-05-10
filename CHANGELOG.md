# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Immunefi platform integration** (`internal/platform/immunefi.go`) — third bug bounty platform alongside HackerOne and Bugcrowd, with program discovery and scope handling.
- **Gitleaks scanner** (`internal/recon/scanner_gitleaks.go`) — secrets scanning integrated into the recon pipeline.
- **Trivy scanner** (`internal/recon/scanner_trivy.go`) — vulnerability and container scanning integrated into the recon pipeline.
- **SARIF v2.1.0 report format** (`internal/report/sarif.go`) — GitHub-uploadable static analysis report output, including security-severity scoring.
- **GitHub issue integration** (`internal/report/github.go`) — automatic GitHub issue creation from findings via the GitHub API.
- **Bulk storage operations** (`internal/storage/bulk.go`) — efficient batched inserts for hosts, endpoints, and findings with partial-failure handling and explicit duplicate counts (issue #14).
- **CVSS 4.0 fields** in the finding model (migration 006) — supports both CVSS 3.1 and 4.0 vectors and version tagging.
- **SSRF protection** in the scan service (`internal/scan/service.go`) — drops URLs that resolve to RFC 1918, cloud metadata, or IPv6 ULA / link-local ranges before passing to external tools.
- **Domain-boundary scope check** (`pkg/validation/project.go`) — `matchesDomain` and `extractHost` helpers with dot-anchored suffix matching, blocking bypass attacks like `evil-example.com` matching in-scope `example.com`. Wildcard patterns (`*.example.com`) supported (PR #16, T0-1 / T0-2).
- **Comprehensive test coverage** for previously-untested modules (12 new test files in PR f62f094 plus per-PR additions); 53+ test files total, all 20 packages green.
- **Standalone `hashpass` utility** (`cmd/hashpass/`) — bcrypt password hashing helper for operators creating accounts manually.
- **Migrate command** (`zerodaybuddy migrate`) — explicit database migration entry point.
- **Project type support** — distinguishes bug-bounty projects from other engagement types (PR #3).

### Changed

- **Auth and middleware modernization** (Phase 2) — bcrypt with refresh tokens, JWT issuance with auto-generated 32-byte secret if not configured, security middleware (CSRF, security headers, rate limiting).
- **Recon pipeline reliability** — fixed 6 critical bugs in scanner orchestration, factory wiring, and result handling (PR 42b1ccb / Phase 1).
- **Go ecosystem modernization** (Phase 3) — dependency updates, Go 1.24 baseline (Tier 1 work bumps to 1.25), modernc.org/sqlite as primary driver.
- **Phases 4 new capabilities** — additional reporting, scanning, and platform features landed across PR #4.
- **Pagination for platform API calls** — HackerOne and Bugcrowd clients now paginate properly (issue #9).
- **Graceful shutdown** — signal handling for clean web server shutdown (issue #11).
- **Configurable logging** — log levels, file rotation via lumberjack, and structured logging in `pkg/utils/logger.go`.

### Fixed

- **Validation test build** (`pkg/validation/project_test.go`) — added missing `matchesDomain` and `extractHost` implementations; package now builds and tests pass (PR #16, T0-1).
- **`:memory:` test config bug** (`internal/core/app_test.go`) — `getTestConfig` now takes `*testing.T` and uses `t.TempDir()` instead of misinterpreting `:memory:` as a SQLite sentinel; no more stray `:memory:/` directories on disk (PR #16, T0-3).
- **Config Save tests** (issue #12) — coverage added for `pkg/config/config.go:Save`.
- **Version command tests** (issue #13) — coverage added for the version command.
- **Bulk operation partial failures** (issue #14) — bulk inserts no longer abort the entire batch on first error; partial successes reported.
- **CodeQL security alerts** addressed across the codebase (PR #3).
- **CodeRabbit review findings** — addressed across multiple iterations (PRs 7ccab2a, 130bfa3, b14c3a4).
- **CI race conditions and lint errors** (PR 092b750).

### Security

- **Domain-boundary scope check** — closes a `strings.Contains` bypass class in `pkg/validation/project.go` (PR #16).
- **SSRF protection** in the scan service blocks scans against internal IPs even if scope validation is misconfigured.
- **JWT secret auto-generation** — refuses to start the web server with the documented insecure development secret; auto-generates and persists a 32-byte hex secret on first run if none is configured.
- **golang.org/x/crypto** bumped to a non-vulnerable version (Dependabot PR #2).
- **Sensitive-data masking** in logs (Phase 2) — passwords, tokens, and API keys are scrubbed before write.

### Infrastructure

- **CI workflows** for build, test, lint, security (govulncheck + gosec), and CodeQL.
- **GoReleaser configuration** (`.goreleaser.yaml`) for multi-platform release builds.
- **golangci-lint configuration** (`.golangci.yml`) with errcheck, govet (enable-all minus fieldalignment), staticcheck, unused, ineffassign, gosimple.
- **Documentation infrastructure** — `docs/brainstorms/`, `docs/plans/`, and `docs/architecture/` directories for durable artifacts; `docs/archive/` for historical session notes (Tier 1 work).

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
