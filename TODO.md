# ZeroDayBuddy TODO

> **The active prioritized backlog lives in [`docs/brainstorms/codebase-punch-list-requirements.md`](docs/brainstorms/codebase-punch-list-requirements.md).** That document is organized by tier (correctness → hygiene → leverage → expansion → polish) with effort estimates, dependency ordering, and rationale for each item.
>
> This `TODO.md` is a thin pointer to the punch list, plus historical record of what's been done. To avoid drift between two parallel priority lists, do not add new "to-do" items here — add them to the brainstorm doc instead.

## Where to find what's pending

| Question | Where to look |
|---|---|
| What's next on correctness? | Punch list — Tier 0 (now closed via PR #16) and Tier 1 (in progress) |
| What's the highest-leverage feature work? | Punch list — Tier 2 (wire the web router) |
| What expands the user base? | Punch list — Tier 3 (manual project mode, hacker workflow) |
| What's the polish backlog? | Punch list — Tier 4 |
| What's explicitly out of scope? | Punch list — "Out of Scope" section (ML, plugin system, alt DB backends, etc.) |
| What's been done? | This file's "Completed" section + `CHANGELOG.md` |

## Completed (post-v0.1.0)

These items were originally listed as "high priority" in earlier versions of this file; they have shipped in subsequent phases of work and are no longer pending.

- [x] Input validation for all user-facing commands (`pkg/validation/`)
- [x] Robust error handling throughout the codebase (`pkg/errors/` + Phases 1-4)
- [x] Unit tests for core components — 53+ test files, all 20 packages green
- [x] Configurable logging system with verbosity levels (`pkg/utils/logger.go`)
- [x] Signal handling for graceful shutdown (issue #11)
- [x] Database migration system (`internal/storage/migrations/`)
- [x] CVSS 4.0 fields in finding model (migration 006)
- [x] SARIF v2.1.0 report support (`internal/report/sarif.go`)
- [x] GitHub issue integration (`internal/report/github.go`)
- [x] Gitleaks scanner integration (`internal/recon/scanner_gitleaks.go`)
- [x] Trivy scanner integration (`internal/recon/scanner_trivy.go`)
- [x] Immunefi platform integration (`internal/platform/immunefi.go`)
- [x] Bulk storage operations with partial failure handling (`internal/storage/bulk.go`, issue #14)
- [x] SSRF protection in scan service (`internal/scan/service.go`)
- [x] Domain-boundary scope check (PR #16, T0-2)
- [x] Pagination for platform API calls (issue #9)
- [x] Test coverage for config Save (issue #12) and version command (issue #13)

## Pre-v0.1.0 baseline

- [x] Basic project management functionality
- [x] Storage interface and SQLite implementation
- [x] Report generation system for findings and projects
- [x] CLI for core functions
- [x] Basic web server scaffold

## Contributing

See `CONTRIBUTING.md` for contribution guidelines. Before starting work on any item from the punch list, check the GitHub issues to see if someone else is already working on it, or open an issue to claim it.

The ZeroDayBuddy team welcomes contributions from developers of all skill levels. Don't hesitate to get involved even if you're new to Go or security tools development.
