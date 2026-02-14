---
title: "Comprehensive E2E Testing and Bug Triage"
type: test
date: 2026-02-13
---

# Comprehensive E2E Testing and Bug Triage

## Overview

ZeroDayBuddy has 39 test files with ~14K lines of test code but significant coverage gaps. 26 modules have zero test coverage, there are zero end-to-end tests, and several bugs were discovered during audit. This plan covers writing tests for all untested functionality and filing GitHub issues for every bug or shortcoming found.

## Problem Statement

The application compiles and existing tests pass, but large portions of the codebase are untested:

- **5 of 10 scanners** have zero test coverage (FFUF, Katana, Wayback, Gitleaks, Trivy)
- **Immunefi platform** — entire integration untested (214 lines)
- **HackerOne report submission** — untested (256 lines)
- **SARIF report generation** — untested (139 lines)
- **GitHub issue creation** — untested (216 lines)
- **SSRF filtering** — security-critical, untested
- **Rate limiting middleware** — untested
- **Bulk storage operations** — untested (201 lines)
- **Web server auth integration** — auth handlers exist but aren't wired into server mux (BUG)
- **PDF report format** — referenced in validation but no generator exists (BUG)

## Bugs and Shortcomings Discovered

These will each become GitHub issues during implementation:

### Bugs (File as `bug`)

| # | Title | Severity | Location | Description |
|---|-------|----------|----------|-------------|
| B1 | Auth handlers never wired into web server | Critical | `internal/web/server.go` | `Server.Start()` creates mux with only `/health` and `/` — auth endpoints from `handlers/auth.go` are never registered. The web server is functionless beyond health checks. |
| B2 | PDF report format accepted but not implemented | Medium | `pkg/validation/validators.go` | Validation accepts "pdf" as valid format, but no PDF generator exists. `report.Service.CreateReport()` only generates markdown. Users get empty/incorrect output. |
| B3 | Scope bypass via `strings.Contains` | High | `pkg/validation/project.go:45-53` | `strings.Contains("http://evil-example.com", "example.com")` returns true, allowing out-of-scope targets to pass validation. Needs domain-boundary-aware check. |
| B4 | `GetProgram` fetches ALL Immunefi bounties on every call | Medium | `internal/platform/immunefi.go:118-133` | `GetProgram()` delegates to `ListPrograms()` which fetches all bounties, then filters. No caching, so N lookups = N full API calls. |
| B5 | No pagination for platform API calls | Low | `internal/platform/hackerone.go`, `bugcrowd.go` | Platform APIs return paginated results but only the first page is fetched. Programs beyond page 1 are silently missing. |

### Shortcomings (File as `enhancement`)

| # | Title | Location | Description |
|---|-------|----------|-------------|
| S1 | Web server middleware not applied | `internal/web/server.go` | SecurityHeaders, CORS, MaxBodySize, RateLimiter middleware exist but aren't applied to any routes. |
| S2 | No graceful shutdown signal handling in `serve` command | `cmd/zerodaybuddy/main.go` | `serve` blocks on `ctx.Done()` but doesn't install signal handlers for SIGTERM/SIGINT. |
| S3 | Config `Save()` never tested | `pkg/config/config.go` | Config can be saved but the save path is never tested — could silently fail. |
| S4 | No test for version command output | `cmd/zerodaybuddy/version.go` | Version command exists but has zero tests. |
| S5 | Bulk operations lack partial failure handling | `internal/storage/bulk.go` | `BulkCreateHosts/Endpoints/Findings` don't handle partial failures within a transaction — one bad record fails the entire batch. |

## Technical Approach

### Testing Strategy

Follow existing patterns in the codebase:
- **Table-driven tests** with `t.Run()` subtests (used in 32 of 39 test files)
- **testify/mock** for dependency injection (used in 5 test files)
- **httptest.NewServer** for HTTP API mocking (used in 7 test files)
- **t.TempDir()** for file system tests
- **Build tag** `//go:build integration` for tests requiring external tools

### Architecture

```
Tests are organized by priority tier:

Tier 1 — Security-Critical Tests (SSRF, scope validation, rate limiting)
Tier 2 — Core Functionality Tests (scanners, platforms, reports)
Tier 3 — Integration Tests (storage bulk ops, web server wiring)
Tier 4 — E2E Pipeline Tests (project → recon → scan → report flow)
```

### Implementation Phases

#### Phase 1: Security-Critical Tests + Bug Issues

Write tests for security-sensitive untested code and file all discovered bugs as GitHub issues.

- [x] **SSRF filtering tests** — `internal/scan/service_ssrf_test.go`
  - `isInternalIP()` with all blocked CIDRs (127.x, 10.x, 172.16.x, 192.168.x, 169.254.x, 0.0.0.0/8, 100.64.x, etc.)
  - `isInternalHost()` with raw IP addresses, hostnames, DNS failures
  - `filterSSRFURLs()` with mixed safe/unsafe URLs, malformed URLs
  - IPv6 addresses (::1, fc00::, fe80::)
  - Edge: hostname that IS an IP address

- [x] **Rate limiting middleware tests** — `internal/web/middleware/ratelimit_test.go`
  - Basic rate limiting (allow under limit, block over limit)
  - Per-IP isolation (different IPs get separate limits)
  - Cleanup of stale entries after TTL
  - `clientIP()` extraction from `RemoteAddr`
  - Concurrent access safety

- [x] **Scope validation tests** — additions to `pkg/validation/validation_test.go`
  - Domain boundary bypass (`evil-example.com` vs `example.com`)
  - Wildcard scope matching
  - URL-to-domain matching edge cases
  - Out-of-scope precedence

- [x] **File all 5 bug issues on GitHub** (B1–B5) — #5, #6, #7, #8, #9
- [x] **File all 5 enhancement issues on GitHub** (S1–S5) — #10, #11, #12, #13, #14

#### Phase 2: Scanner Tests

Write tests for the 5 untested scanners. Each scanner follows the same pattern: construct scanner, mock exec output, verify result parsing and scope filtering.

- [x] **FFUF scanner tests** — `internal/recon/scanner_ffuf_test.go`
  - `DiscoverEndpoints()` with mock FFUF JSON output
  - Config path fallback (FFUFPath vs default "ffuf")
  - Scope filtering of discovered endpoints
  - Wordlist handling
  - Error handling (tool not found, invalid output)

- [x] **Katana scanner tests** — `internal/recon/scanner_katana_test.go`
  - `DiscoverEndpoints()` with mock Katana JSON output
  - ProjectID propagation in `katanaResultToEndpoint()`
  - Depth option handling
  - Out-of-scope URL filtering
  - Multiple URL input

- [x] **Wayback scanner tests** — `internal/recon/scanner_wayback_test.go`
  - `DiscoverEndpoints()` with mock CDX API response
  - ProjectID propagation in `waybackResultToEndpoint()`
  - Rate-limited HTTP client usage
  - URL deduplication
  - Timestamp parsing edge cases
  - Scope filtering

- [x] **Gitleaks scanner tests** — `internal/recon/scanner_gitleaks_test.go`
  - Secret detection result parsing
  - Unique output file per target
  - Finding creation from gitleaks results
  - Config path fallback

- [x] **Trivy scanner tests** — `internal/recon/scanner_trivy_test.go`
  - `ScanVulnerabilities()` with mock Trivy JSON output
  - CVE-to-References mapping (not CWE)
  - Severity mapping
  - Stderr capture via bytes.Buffer
  - Non-zero exit with valid output (partial results)
  - Severity validation

#### Phase 3: Platform and Report Tests

- [x] **Immunefi platform tests** — `internal/platform/immunefi_test.go`
  - `ListPrograms()` — success, empty, paused programs filtered, API error, invalid JSON
  - `GetProgram()` — found, not found, case-insensitive match
  - `FetchScope()` — various asset types, URL path escaping, API error
  - `immunefiAssetType()` mapping — smart_contract, web, blockchain, github, unknown
  - Rate-limited HTTP client integration
  - Context cancellation

- [x] **HackerOne report submission tests** — `internal/platform/hackerone_report_test.go`
  - `SubmitReport()` end-to-end with 3-step flow (mock HTTP)
  - `createReportIntent()` — success, auth failure, missing credentials
  - `updateReportIntent()` — success, 404
  - `submitReportIntent()` — success, conflict
  - `formatReportBody()` — with all finding fields, minimal fields
  - `mapSeverityToHackerOne()` — all severity levels

- [x] **SARIF report tests** — `internal/report/sarif_test.go`
  - `GenerateSARIF()` — with findings, empty findings, multiple findings same CWE
  - `ruleIDFromFinding()` — with CWE, without CWE
  - `sarifLevel()` — critical→error, high→error, medium→warning, low→note, info→note
  - `securitySeverity()` — with CVSS score, without (severity-based fallback)
  - Rule deduplication (seenRules map)
  - Valid SARIF v2.1.0 output structure

- [x] **GitHub issue creation tests** — `internal/report/github_test.go`
  - `CreateIssueFromFinding()` — with various finding types
  - `formatIssueTitle()` — title generation
  - `formatIssueBody()` — body markdown generation with all fields
  - `issueLabels()` — label generation by severity

#### Phase 4: Storage and Infrastructure Tests

- [x] **Bulk storage operation tests** — `internal/storage/bulk_test.go`
  - `BulkCreateHosts()` — success, empty input, duplicate handling, foreign key violation
  - `BulkCreateEndpoints()` — success, empty, large batch
  - `BulkCreateFindings()` — success, empty, JSON field serialization
  - Transaction atomicity (all-or-nothing on error)
  - Performance with large batches (100+ records)

- [ ] **Storage error wrapping tests** — `internal/storage/errors_impl_test.go`
  - Error type identification and wrapping
  - pkgerrors integration
  - ErrNotFound and ErrConflict propagation

- [ ] **Finding NULL handling tests** — additions to `internal/storage/store_test.go`
  - Create finding with NULL CWE column
  - Create finding with NULL JSON columns
  - Hydration of findings with mixed NULL/non-NULL fields

- [ ] **Rate-limited HTTP client tests** — `pkg/ratelimit/client_test.go`
  - `HTTPClient.Get()` — success, rate limited, retry on 429
  - `HTTPClient.Do()` — custom requests
  - Timeout handling
  - Retry with exponential backoff
  - Context cancellation during retry

- [ ] **Project validation tests** — `pkg/validation/project_test.go`
  - Project name validation
  - Scope validation rules
  - Domain boundary checking

#### Phase 5: E2E Pipeline Tests

- [ ] **Full pipeline test** — `internal/core/e2e_test.go`
  - Create project with mock platform → verify stored in DB
  - Run recon with mock scanners → verify hosts/endpoints stored
  - Run scan with mock nuclei → verify findings stored
  - Generate report → verify report content includes findings
  - Full data flow: platform → project → recon → scan → finding → report

- [ ] **CLI command tests** — additions to `cmd/zerodaybuddy/main_test.go`
  - `version` command output verification
  - `serve` command with custom host/port
  - `init` command creates config and database
  - Error messages for missing required flags

- [ ] **Web server integration test** — `internal/web/server_integration_test.go`
  - Verify auth endpoints ARE registered (after fixing B1)
  - Full request flow: register → login → access protected resource → logout
  - Rate limiting integration
  - Security headers applied

## Acceptance Criteria

### Functional Requirements

- [x] All 5 untested scanners have test files with >80% coverage
- [x] Immunefi platform has comprehensive test coverage
- [x] HackerOne report submission has test coverage for the 3-step flow
- [x] SARIF and GitHub report generation have test coverage
- [x] SSRF filtering has tests for all CIDR ranges and edge cases
- [x] Rate limiting middleware has concurrency and TTL tests
- [x] Bulk storage operations have atomicity and edge case tests
- [ ] At least one E2E test covers the full pipeline (project → report)
- [x] All tests pass with `go test ./... -short -race`

### Bug Issues Filed

- [x] B1: Auth handlers not wired into server (critical) — #5
- [x] B2: PDF format accepted but not implemented (medium) — #6
- [x] B3: Scope bypass via strings.Contains (high) — #7
- [x] B4: Immunefi GetProgram fetches all bounties (medium) — #8
- [x] B5: No pagination for platform APIs (low) — #9

### Enhancement Issues Filed

- [x] S1: Web server middleware not applied — #10
- [x] S2: No graceful shutdown signal handling — #11
- [x] S3: Config Save() untested — #12
- [x] S4: Version command untested — #13
- [x] S5: Bulk operations lack partial failure handling — #14

### Quality Gates

- [x] All existing tests continue to pass (no regressions)
- [x] New tests follow table-driven pattern with subtests
- [x] New tests use testify/mock for external dependencies
- [x] No tests require external tools (unit tests only, integration tests behind build tags)
- [x] `go test ./... -short -race` passes cleanly

## References & Research

### Internal References

- Existing test patterns: `internal/platform/hackerone_test.go` (gold standard for HTTP API mock tests)
- Mock store pattern: `internal/scan/service_test.go:17-82`
- Scanner test pattern: `internal/recon/scanner_subfinder_test.go`
- Storage test setup: `internal/storage/store_test.go:setupTestStore()`
- CI configuration: `.github/workflows/ci.yml`

### Test Files Inventory

| Package | Existing Tests | Files Needing Tests |
|---------|---------------|---------------------|
| `internal/scan` | `service_test.go` | `service_ssrf_test.go` (new) |
| `internal/recon` | 7 test files | `scanner_{ffuf,katana,wayback,gitleaks,trivy}_test.go` (5 new) |
| `internal/platform` | 3 test files | `immunefi_test.go`, `hackerone_report_test.go` (2 new) |
| `internal/report` | `service_test.go` | `sarif_test.go`, `github_test.go` (2 new) |
| `internal/storage` | `store_test.go` | `bulk_test.go`, `errors_impl_test.go` (2 new) |
| `internal/web/middleware` | 3 test files | additions to `ratelimit_test.go` (exists but empty) |
| `pkg/ratelimit` | 2 test files | `client_test.go` (1 new) |
| `pkg/validation` | 2 test files | `project_test.go` (1 new) |
| `internal/core` | `app_test.go` | `e2e_test.go` (1 new) |
| `internal/web` | `server_test.go` | `server_integration_test.go` (1 new) |

**Total new test files: ~16**
**Total GitHub issues to file: 10** (5 bugs + 5 enhancements)
