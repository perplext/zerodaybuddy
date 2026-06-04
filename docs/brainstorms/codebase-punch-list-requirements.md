# ZeroDayBuddy Codebase Punch List — Requirements

**Date:** 2026-05-10
**Branch at audit:** `fix/github-issues-9-12-13-14`
**Audit scope:** full repo (≈30,954 LoC Go, 53 test files, 6 SQL migrations, web template assets)
**Ranking:** correctness-first (broken → security/safety → leverage → expansion)
**Source workflow:** `/compound-engineering:ce-brainstorm`
**Successor:** suitable for `/ce-plan` per tier, or `/ce-work` per item

---

## 1. Goal

Produce a prioritized, actionable backlog of every meaningful gap surfaced by a verification-first audit of the codebase, so future sessions (`ce-plan`, `ce-work`) can pull items off the top without re-discovering context.

The audit answered four sub-questions:

1. **What works?** — capabilities that are implemented and verified.
2. **What's broken?** — code that fails to build, fails tests, or contains live correctness/security defects.
3. **What's missing?** — design-level gaps that block real workflows (not just nice-to-haves).
4. **What's under-implemented?** — capability that is built but unreachable from the user surface (CLI/web).

---

## 2. Audit Summary

**What works (verified by reading current source, not docs):**

| Area | Status |
|---|---|
| Architecture | Clean `cmd / internal / pkg` separation; `App` orchestrator wires services with `ensureInitialized` |
| Storage | SQLite via `internal/storage`; 6 ordered SQL migrations including CVSS fields and auth tables |
| Recon | 10 scanners present: subfinder, amass, httpx, naabu, katana, wayback, ffuf, nuclei, gitleaks, trivy |
| Scan service | `internal/scan/service.go` — real implementation with nuclei orchestration, hardened SSRF filter (RFC 1918 + cloud-metadata + IPv6), semaphore concurrency, batch processing, finding ingest |
| Auth | bcrypt password hashing; JWT with auto-generated 32-byte secret; refresh tokens; SQLStore on shared DB |
| Reports | JSON + CSV + SARIF v2.1.0 + GitHub integration |
| Models | Wildcard + CIDR + subdomain scope matching at `pkg/models/models.go:115`; CVSS 3.1/4.0 fields |
| Rate limiting | Per-service limiter with cleanup ticker |
| CLI | `init`, `list-programs`, `project`, `recon`, `scan`, `report`, `serve`, `version` all wired |
| Tests | 22 of 23 test packages pass; only `pkg/validation` fails (build error, not assertion) |

**What's broken or unwired (verified):**

- `pkg/validation/project_test.go` references undefined `matchesDomain` and `extractHost` — `go test ./...` fails to build this package.
- `pkg/validation/project.go:48` uses `strings.Contains(target, asset.Value)` for scope matching (CWE-bypass-class) — but is **dead code** (only the broken test references `ProjectScope`).
- `internal/web/server.go` registers only `/health` and a static welcome page; the full handler/middleware stack at `internal/web/handlers/` and `internal/web/middleware/` (auth, errors, ratelimit, security) is **never wired**.
- `internal/core/:memory:/` and `cmd/zerodaybuddy/:memory:/` — directories accidentally created by something opening SQLite with `":memory:"` as a filename.

**What's stale or misleading:**

- `CLAUDE.md` claims scan service is "currently stub" (false); doesn't mention gitleaks/trivy scanners or SARIF/GitHub report modules.
- `TODO.md` lists already-completed items as "high priority" (signal handling, JWT secret, log levels, error handling).
- `CHANGELOG.md` `[Unreleased]` is empty despite Phases 1-4 of modernization having merged.
- Five `scratch-*.md` files plus `HACKERONE_HACKER_LIMITATIONS.md`, `create_manual_project.sql`, `test_server.py`, `ZERODAYBUDDY_TEST_REPORT.md` clutter the repo root.

---

## 3. The Punch List

Each item: **what** + **where** + **effort (S/M/L)** + **why this rank** + **dependencies**.

### Tier 0 — Broken (fix immediately; blocks other work)

**T0-1. Fix `pkg/validation/project_test.go` build break**
- Where: `pkg/validation/project_test.go` (untracked)
- Effort: S
- Two clean options: (a) implement `matchesDomain` + `extractHost` in `pkg/validation/project.go` and fix `ProjectScope` to use them, or (b) delete the test file as part of T0-2 if `ProjectScope` itself goes.
- Why first: blocks `go test ./...` from green; signals abandoned in-progress work that confuses future contributors.

**T0-2. Resolve duplicate scope-checking implementations**
- Where: `pkg/validation/project.go:33` (`ProjectScope`)
- Effort: S (delete) or M (fix and integrate)
- The vulnerable `strings.Contains` path is currently unreachable from production code (only its test references it), but it's a footgun: anyone wiring `ProjectScope` into a real handler regresses the security check that `models.IsInScope` already does correctly.
- Recommended: **delete** `ProjectScope` and the `isURL` helper, and have callers use `models.Scope.IsInScope()` directly.

**T0-3. Clean up `:memory:` literal directories**
- Where: `internal/core/:memory:/`, `cmd/zerodaybuddy/:memory:/`
- Effort: S
- Find what opens SQLite with `":memory:"` as a filesystem path (likely a test or CLI default that misinterprets the SQLite in-memory sentinel) and patch it. Then `rm -rf` the stray directories. Add `:memory:/` to `.gitignore` as a belt-and-suspenders.
- Why first: low cost, signals correctness, rules out a path-handling bug elsewhere.

### Tier 1 — Stale and misleading (small effort, high trust gain)

**T1-1. Update `CLAUDE.md` to match reality**
- Where: `CLAUDE.md`
- Effort: S
- Remove the "scan service is currently stub" claim; document gitleaks/trivy scanners; document SARIF and GitHub report modules; explicitly note that the web UI is not yet wired (so future Claude sessions don't assume it works).

**T1-2. Refresh `TODO.md`**
- Where: `TODO.md`
- Effort: S
- Remove items completed in Phases 1-4: signal handling, JWT secret generation, log level config, error handling standardization.
- Move "Future Considerations" (ML, plugin system, alt DB backends) to `docs/future-ideas.md` or delete — they currently muddy the priority signal.

**T1-3. Populate `CHANGELOG.md` `[Unreleased]`**
- Where: `CHANGELOG.md`
- Effort: S
- Document Phases 1-4 modernization, recent issue fixes (#9, #12, #13, #14), scanner additions (gitleaks, trivy), SARIF support, GitHub report integration.

**T1-4. Archive scratch and one-off files**
- Where: repo root
- Effort: S
- Move to `docs/archive/` or delete: `scratch-gap-analysis.md`, `scratch-issues-progress.md`, `scratch-research-notes.md`, `scratch-research-2026.md`, `scratch-security-standards-research.md`, `HACKERONE_HACKER_LIMITATIONS.md`, `ZERODAYBUDDY_TEST_REPORT.md`, `create_manual_project.sql`, `test_server.py`.
- Note: extract any still-actionable items into this punch list before archiving (already done for the major ones).

### Tier 2 — Finish the iceberg (high leverage; built code currently dark)

**T2-1. Wire the web router**
- Where: `internal/web/server.go`
- Effort: L (significant, but every line of dependency code already exists)
- Replace the stub mux with a real router (chi or net/http with method routing) that:
  - Registers `AuthHandler` (`internal/web/handlers/auth.go`) at `/api/auth/login`, `/api/auth/refresh`, `/api/auth/logout`.
  - Applies middleware in the correct order: `RecoverPanic` → `SecurityHeaders` → `RateLimit` → `Auth` (per-route).
  - Serves static assets from `web/static/`.
  - Loads templates from `web/templates/` via `html/template`.
- Wire dependencies through `App.RegisterService` calls in `internal/core/app.go:Initialize`.
- Why this tier: turns the project from "CLI with placeholder web stub" into "CLI + functional web app". Single biggest user-visible improvement per hour spent.
- Depends on: nothing.
- Blocks: T2-2, T2-3, all Tier 4 web work.

**T2-2. Add data-model REST handlers**
- Where: new files under `internal/web/handlers/` (projects.go, hosts.go, endpoints.go, findings.go, tasks.go)
- Effort: M-L
- Minimum: GET (list, by-id), POST (create), DELETE for projects + read-only GETs for hosts/endpoints/findings/tasks. Mutation endpoints for findings (status change, severity override).
- Wire via T2-1's router.
- Depends on: T2-1.

**T2-3. Templates and static-asset pipeline**
- Where: `internal/web/server.go`, `web/templates/`, `web/static/`
- Effort: M
- Wire `html/template` parsing at startup; serve `/static/*` from `web/static/`; render dashboard, project list, project detail, scan-detail, findings pages.
- Inspect what templates are currently in `web/templates/` and align with what handlers need.
- Depends on: T2-1.

> **Status (2026-06-03):** Tier 3 implemented on branch `feat/tier-3-surface-expansion` — manual project mode (CLI + web), scope file schema/loader (`pkg/models/scopefile.go`, `examples/scope.{yaml,json}`), and HackerOne hacker-tier 401 clarification. Plan: `docs/plans/2026-06-03-001-feat-tier-3-surface-expansion-plan.md`.

### Tier 3 — Surface expansion (new capability; addresses real-user blockers)

**T3-1. Manual project mode**
- Where: `pkg/validation/validation.go`, `internal/core/app.go`, `cmd/zerodaybuddy/main.go`
- Effort: M
- Add a `"manual"` platform type. New CLI: `zerodaybuddy project create --manual --name X --scope-file scope.{yaml,json}`.
- `App.CreateProject` factored to accept either `(platform, programHandle)` or `(scopeDoc)`.
- Why valuable: directly unblocks individual hackers (who can't use HackerOne org-tier API) and arbitrary security work. Addresses concerns documented in `HACKERONE_HACKER_LIMITATIONS.md` and `ZERODAYBUDDY_TEST_REPORT.md`. Materially expands the addressable user base.
- Depends on: nothing structurally; benefits from T2-2 if web-based project creation is wanted.

**T3-2. Scope file schema**
- Where: new `pkg/models/scopefile.go` + example in `examples/scope.yaml`
- Effort: S-M
- Define a YAML/JSON schema covering: `in_scope[]`, `out_of_scope[]`, asset types (`url`, `domain`, `ip`, `cidr`, `wildcard`, `mobile-android`, `mobile-ios`, `code`, `executable`, `hardware`, `other`).
- Aligns with HackerOne and Bugcrowd asset taxonomies (per `scratch-security-standards-research.md`).
- Depends on: T3-1.

**T3-3. HackerOne hacker-account workflow clarification**
- Where: `internal/platform/hackerone.go`, `cmd/zerodaybuddy/main.go`
- Effort: M
- Detect when a token has hacker-tier (not org-tier) permissions; emit a clear error with a pointer to manual mode (T3-1). Optionally: support hacker-side endpoints where they exist (e.g. `/v1/hackers/me`).
- Mostly clarification + error-message work; not a full alternate API client.
- Depends on: T3-1 (so the error message can recommend manual mode).

### Tier 4 — Polish / nice-to-have (only after Tier 0-3)

- **T4-1.** Verify pagination across all platform clients post-#9 merge.
- **T4-2.** Real-time scan progress via SSE or WebSocket (depends on T2-1).
- **T4-3.** Scan scheduling (cron-style).
- **T4-4.** Findings export to HackerOne/Bugcrowd report submission formats (depends on T3-1, T3-2).
- **T4-5.** Scan-over-time comparison view (depends on T2-2).

---

## 4. Out of Scope

- Machine-learning vulnerability prediction (TODO.md "Future Considerations").
- Plugin/extension system (TODO.md "Future Considerations").
- Alternate DB backends — SQLite is sufficient for the use case; rip out the TODO line.
- Multi-user RBAC — auth tables exist but no concrete demand; revisit when there's a second user.
- Slack/Discord notifications, JIRA/GitHub issue tracker integration.
- Two-factor authentication.
- Bug bounty program for the tool itself.

---

## 5. Open Questions

These shape Tier 2 and Tier 3 priority. Worth answering before pulling Tier 2 work off the top.

1. **Is the web UI actually a goal?** If the project has effectively pivoted to CLI-first, Tier 2 is wasted leverage. If not, Tier 2 is the biggest win per hour.
2. **Are there active users besides the maintainer?** Affects whether T1-* cleanups need migration notes and whether T3-* gets prioritized over polish.
3. **Is "individual hacker" a real target persona?** If yes, T3-1 jumps in priority above some Tier 2 items. If no, T3-* drops.
4. **Is there a release cadence?** Affects whether T1-3 (CHANGELOG) is decorative or load-bearing.

---

## 6. Dependency Graph (compact)

```
T0-1 ─┐
T0-2 ─┼── independent ──> green test suite
T0-3 ─┘

T1-1, T1-2, T1-3, T1-4 ─── all independent

T2-1 ──┬─> T2-2 ──┬─> T4-2, T4-5
       └─> T2-3 ──┘

T3-1 ──┬─> T3-2 ──> T4-4
       └─> T3-3
```

Tier 0 + Tier 1 can land in parallel with no blockers. Tier 2 has internal sequencing (T2-1 first). Tier 3 has internal sequencing (T3-1 first).

---

## 7. Suggested Sequence (correctness-first)

| Window | Items | Outcome |
|---|---|---|
| Session 1 | T0-1, T0-2, T0-3 | Test suite fully green; dead code removed; cosmetic dirs gone |
| Session 2 | T1-1, T1-2, T1-3, T1-4 | Docs match reality; repo root clean; trust-in-repo restored |
| Sessions 3-5 | T2-1 | Web router wired; auth flow live; static assets served |
| Sessions 6-8 | T2-2, T2-3 | Data-model handlers + templates live; web UI usable |
| Sessions 9-10 | T3-1, T3-2 | Manual project mode + scope file schema |
| Session 11 | T3-3 | Hacker-account UX clarification |
| Future | Tier 4 as demand surfaces |

---

## 8. Success Criteria

The punch list is "done" when:

- `go test ./...` runs to completion with zero build failures (T0-1).
- `grep -rn "strings.Contains.*Value" pkg/` returns no scope-check results (T0-2).
- `find . -path "*/:memory:*"` returns nothing (T0-3).
- `CLAUDE.md`, `TODO.md`, `CHANGELOG.md` accurately describe the codebase as it actually exists (T1-*).
- `curl http://localhost:8080/api/auth/login` does something other than 404 (T2-1).
- `zerodaybuddy project create --manual --name foo --scope-file ex.yaml` produces a working project (T3-1).

Each tier's success criteria should be its own verification gate before moving to the next.
