---
title: "refactor: Tier 1 hygiene — docs accuracy, scratch cleanup, and CI stabilization"
date: 2026-05-10
type: refactor
depth: standard
status: active
origin: docs/brainstorms/codebase-punch-list-requirements.md
related_units: U1, U2, U3, U4, U5
---

# Tier 1 Hygiene Plan

## Summary

Land all five Tier 1 punch-list items in a single PR that ends with: docs trustworthy, repo root clean, CI fully green on every check.

| Unit | Origin | Effort | Behavior change? |
|---|---|---|---|
| U1 | T1-1 (CLAUDE.md refresh) | S | No |
| U2 | T1-2 (TODO.md refresh) | S | No |
| U3 | T1-3 (CHANGELOG.md `[Unreleased]`) | S | No |
| U4 | T1-4 (archive scratch files) | S | No |
| U5 | T1-5 (stabilize CI) | M | Yes — Go version + lint config + 2 source files |

T1-5 was added to the punch list in this session after PR #16 surfaced two evergreen-red CI checks (`lint` and `security`) — both unrelated to PR #16's diff, both failing on every recent PR including the previously-merged #15. See Key Technical Decisions D1-D4 for the CI-stabilization choices.

---

## Problem Frame

After Tier 0 closed (PR #16 merged), three documentation files lie about the codebase, the repo root is cluttered with session artifacts, and CI emits chronic false-failure noise on `lint` and `security` checks that block nobody but degrade signal quality:

- **`CLAUDE.md`** — claims `internal/scan/` is "currently stub implementation" (false — it's 484 lines of real nuclei orchestration with SSRF protection); doesn't mention the gitleaks/trivy scanners or SARIF/GitHub report modules; doesn't note that the web UI is built but unwired (the single biggest gotcha for any agent reading this file).
- **`TODO.md`** — lists "Implement input validation", "Add robust error handling", "Improve logging system", and "Implement proper signal handling" as "high priority" — all completed in Phases 1-4 modernization or the recent issue fixes (#11 closed signal handling).
- **`CHANGELOG.md` `[Unreleased]`** — empty section despite massive Phase 1-4 work, the Immunefi platform addition, six issue fixes (#9, #11, #12, #13, #14, #16), and several scanner/report capability additions all having merged.
- **Repo root** — five `scratch-*.md` analysis files, `HACKERONE_HACKER_LIMITATIONS.md`, `ZERODAYBUDDY_TEST_REPORT.md`, `create_manual_project.sql`, `test_server.py` — all session artifacts that obscure the canonical project files.
- **CI `lint` and `security` checks** — fail on every recent PR for reasons unrelated to the PR's diff: Go stdlib CVEs requiring Go 1.25 (project on 1.24.0), `golangci-lint version: latest` picking up new rules (`unusedwrite`, deprecated `io/ioutil`) that fire on pre-existing code.

---

## Requirements Trace

From `docs/brainstorms/codebase-punch-list-requirements.md`:

- **T1-1** Update `CLAUDE.md` to match reality → **U1**
- **T1-2** Refresh `TODO.md` → **U2**
- **T1-3** Populate `CHANGELOG.md` `[Unreleased]` → **U3**
- **T1-4** Archive scratch and one-off files → **U4**
- **T1-5** *(plan-time addition)* Stabilize CI infrastructure → **U5**. This item is not in the origin brainstorm; it was surfaced during PR #16's CI run and added to the punch list at session-end. See D6 for why it lives here rather than getting back-ported to the brainstorm.

Tier 1 success criteria from origin (paraphrased):

- Docs accurately describe the codebase as it actually exists.
- Repo root cleaned of session artifacts.
- (D6 added) Merge gate green end-to-end on subsequent PRs.

---

## Key Technical Decisions

### D1. Bump Go to `1.25.0` in `go.mod` and CI matrix

The 7 stdlib CVEs reported by `govulncheck` on PR #16 (GO-2026-4971 net dialer, GO-2026-4947/4946 crypto/x509, GO-2026-4918 net/http HTTP/2, GO-2026-4870 crypto/tls KeyUpdate DoS, GO-2026-4602 os FileInfo escape, GO-2026-4601 net/url IPv6 parsing) all have fixes in Go 1.25.x. `govulncheck v1.3.0` itself requires Go 1.25 to run.

Going `1.24.0` → `1.25.0` directly. Not adding a `toolchain` directive — the project doesn't have multi-version-Go contributors and the directive adds complexity for no current benefit. If a future contributor needs to support older Go, they can add the directive then.

### D2. Pin `golangci-lint` to a specific version, not `latest`

PR #16 failed `lint` because `golangci-lint-action@v6` with `version: latest` picked up newer linter releases that introduced `unusedwrite` (a govet sub-analyzer) and tightened `staticcheck`'s deprecated-API detection — neither of which existed when the affected code was written. `latest` makes CI a moving target; pinning makes it reproducible.

Recommendation: pin to whatever is the current stable at execution time (was `v1.64.8` when PR #16 ran). The implementer should check `https://github.com/golangci/golangci-lint/releases` and pick the latest stable patch.

### D3. Disable `govet/unusedwrite` analyzer globally

The `unusedwrite` analyzer flags struct-literal fields that are written but never subsequently read. The flagged sites in `pkg/models/models_test.go` are test fixtures that intentionally set every field of a struct — a documentation pattern that shows the test what shape the struct has, even when the test only asserts on a subset of fields.

Three fix options were considered:
1. Add `//nolint:govet` to every flagged test function — noisy, ~14 annotations
2. Remove the unused field assignments — loses test fidelity; the struct shape becomes implicit
3. Disable `unusedwrite` globally in `.golangci.yml` — one line, removes the false-positive class entirely

Option 3 wins. Production code rarely uses unused-write patterns; the loss-of-signal in real code is minimal. The relevant linter setting goes alongside the existing `fieldalignment` disable.

### D4. Replace `io/ioutil` with `io` and `os` equivalents (mechanical)

`io/ioutil` has been deprecated since Go 1.19. `pkg/utils/utils.go:6` is the only import site flagged. Standard mapping: `ioutil.ReadAll` → `io.ReadAll`, `ioutil.ReadFile` → `os.ReadFile`, `ioutil.WriteFile` → `os.WriteFile`, `ioutil.TempFile`/`TempDir` → `os.CreateTemp`/`MkdirTemp`. Permanent fix; no behavior change.

### D5. One PR for all five units, five commits

Brainstorm grouped these as Tier 1. Same risk profile (low). Same review type (mostly mechanical). Bundling closes the tier as one unit of work, matching the Tier 0 PR pattern.

Five commits, one per unit, lets the reviewer skim each independently. Doc commits (U1, U2, U3) could be squashed if desired, but separation keeps each tier item traceable in `git log`.

### D6. T1-5 stays plan-local; not back-ported into the brainstorm doc

T1-5 was discovered post-brainstorm at execution time (PR #16's CI). Updating `docs/brainstorms/codebase-punch-list-requirements.md` to add T1-5 retroactively would conflate "what we knew at audit" with "what we discovered during execution" and reduce the brainstorm's value as a snapshot.

This plan documents T1-5 as a plan-time addition with explicit reference to PR #16's CI experience. Future tier audits can pick up T1-5 from the plan or from a future brainstorm refresh.

---

## Implementation Units

### U1. Refresh CLAUDE.md to match reality

**Goal:** `CLAUDE.md` should accurately describe what's in the codebase, so future agent sessions don't operate on stale assumptions (e.g., trying to extend a "stub" scan service that's actually 484 lines of real code).

**Requirements:** T1-1.

**Dependencies:** None.

**Files:**
- `CLAUDE.md` (modify)

**Approach:**
- Remove the "currently stub implementation" claim about `internal/scan/`. Replace with an accurate one-liner: "Vulnerability scanning service with Nuclei orchestration, SSRF filtering, semaphore concurrency, and finding ingest."
- Update the "Integrated Security Tools" list to add `gitleaks` (secrets scanning) and `trivy` (vulnerability/container scanning). Confirm the existing 7 scanners are still listed.
- Add a section or note under "Project Status" or near the web-server reference: "Web UI handlers (`internal/web/handlers/`) and middleware (`internal/web/middleware/`) are implemented but **not wired** into `internal/web/server.go` — currently only `/health` and a static welcome page are served. See `docs/brainstorms/codebase-punch-list-requirements.md` Tier 2 for the wiring plan."
- Add report capability accuracy: SARIF v2.1.0 (`internal/report/sarif.go`) and GitHub issue integration (`internal/report/github.go`).
- Verify the "Test Coverage" claim is accurate (53 test files; 20/20 packages green post-PR #16).
- Add a one-line cross-reference at the top: "For project punch-list and active priorities, see `docs/brainstorms/codebase-punch-list-requirements.md`."

**Patterns to follow:**
- Match the existing CLAUDE.md prose style (concise, factual, no emoji except where already present).
- Section ordering should stay as-is; only edit content within existing sections.

**Test scenarios:** none — pure documentation file with no behavior to test.

**Verification:**
- The phrase "currently stub" no longer appears in `CLAUDE.md`.
- `gitleaks`, `trivy`, `SARIF`, `GitHub` all appear in the relevant tool/capability lists.
- The web-UI-unwired note is present.

---

### U2. Refresh TODO.md (remove completed items, anchor on punch list)

**Goal:** `TODO.md` should reflect what's actually pending, not what was done two phases ago. Future contributors who skim it should get accurate priority signal.

**Requirements:** T1-2.

**Dependencies:** None.

**Files:**
- `TODO.md` (modify)

**Approach:**
- Remove from "High Priority Tasks → Core Functionality": "Implement input validation" (done — `pkg/validation/`), "Add robust error handling" (done — `pkg/errors/` plus Phases 1-4), "Create unit tests for core components" (done — 53 test files, all packages green), "Improve logging system with configurable verbosity levels" (done — `pkg/utils/logger.go`), "Implement proper signal handling" (done — issue #11).
- Remove or strike any other items that have shipped per `git log` — review each high-priority item against current code.
- Replace the "Future Considerations" section with a pointer to the brainstorm doc as the canonical priority source: "See `docs/brainstorms/codebase-punch-list-requirements.md` for the active prioritized backlog."
- Optional: keep `TODO.md` as a thin index pointing to the brainstorm doc rather than maintaining two parallel lists. This avoids the same drift recurring.

**Patterns to follow:**
- Existing TODO.md uses GitHub-task-list `- [ ]` checkboxes — preserve the format.
- If keeping items, group them by tier (Tier 2, Tier 3, Tier 4) to match the brainstorm.

**Test scenarios:** none — pure documentation file.

**Verification:**
- Items checked as done in this plan no longer appear as "high priority".
- Cross-reference to brainstorm doc is present.

---

### U3. Populate CHANGELOG.md `[Unreleased]`

**Goal:** The `[Unreleased]` section should list everything between v0.1.0 (2025-06-19) and the current main, so when v0.2.0 cuts, the release notes are already written.

**Requirements:** T1-3.

**Dependencies:** None.

**Files:**
- `CHANGELOG.md` (modify)

**Approach:**
- Use Keep-a-Changelog section convention: `Added`, `Changed`, `Fixed`, `Security`, `Infrastructure`.
- Source material (review `git log v0.1.0..main` to confirm coverage):
  - **Added:** Immunefi platform integration (`internal/platform/immunefi.go`), gitleaks scanner (`internal/recon/scanner_gitleaks.go`), trivy scanner (`internal/recon/scanner_trivy.go`), SARIF v2.1.0 report (`internal/report/sarif.go`), GitHub issue integration (`internal/report/github.go`), CVSS 4.0 fields in models (migration 006), bulk operations with partial failure handling (`internal/storage/bulk.go`), SSRF protection in scan service, scope file validation, comprehensive test coverage for 12 previously untested modules.
  - **Changed:** Modernized Go ecosystem (Phase 3), refactored auth/middleware, hardened security infrastructure (Phase 2).
  - **Fixed:** Issue #5 (auth wiring — partial), #9 (pagination), #11 (graceful shutdown), #12 (config Save tests), #13 (version tests), #14 (bulk partial failures), #16 (Tier 0 correctness — validation security fix + `:memory:` test bug), recon/scan pipeline 6 critical bugs.
  - **Security:** Validation domain-boundary fix (PR #16), SSRF protection, additional CodeRabbit-identified findings.
- Date the section as ongoing (no date until release).

**Patterns to follow:**
- Existing v0.1.0 entry's section structure (Added, Security, Infrastructure subsections under each version).
- Keep-a-Changelog format.

**Test scenarios:** none — pure documentation file.

**Verification:**
- `[Unreleased]` is no longer empty.
- All commits in `git log v0.1.0..main` map to at least one CHANGELOG line (or are intentionally omitted as not-user-facing).

---

### U4. Archive scratch and one-off files at repo root

**Goal:** Repo root should contain only canonical project files. Session artifacts move to `docs/archive/` so they remain available for reference (especially `HACKERONE_HACKER_LIMITATIONS.md` which informs Tier 3 work) but don't clutter the top-level directory.

**Requirements:** T1-4.

**Dependencies:** None.

**Files:**
- Create `docs/archive/` directory.
- Create `docs/archive/README.md` (new) noting that contents are historical artifacts not actively maintained.
- Move (preserve git history with `git mv`):
  - `scratch-gap-analysis.md` → `docs/archive/`
  - `scratch-issues-progress.md` → `docs/archive/`
  - `scratch-research-notes.md` → `docs/archive/`
  - `scratch-research-2026.md` → `docs/archive/`
  - `scratch-security-standards-research.md` → `docs/archive/`
  - `HACKERONE_HACKER_LIMITATIONS.md` → `docs/archive/` (informs Tier 3)
  - `ZERODAYBUDDY_TEST_REPORT.md` → `docs/archive/` (historical test session)
- Delete (these have no future reference value):
  - `create_manual_project.sql` — superseded by upcoming Tier 3 manual-project mode (T3-1)
  - `test_server.py` — orphaned ad-hoc Python file from a long-past test session

**Approach:**
- These files are currently untracked in git (per `git status` at session start). For untracked files, `git mv` is unnecessary — just `mv`. Then `git add docs/archive/`.
- For `create_manual_project.sql` and `test_server.py`, simply `rm` since they're untracked.
- The `docs/archive/README.md` should briefly explain: "Files in this directory are historical artifacts from prior sessions — research notes, gap analyses, test reports, design documents — preserved for context but not actively maintained. For current state of the project, see top-level docs."

**Patterns to follow:**
- `docs/` already exists with `architecture/`, `brainstorms/`, `img/`, `plans/` subdirectories. `archive/` fits the convention.

**Test scenarios:** none — file move/delete only, no behavior change.

**Verification:**
- `find . -maxdepth 1 -name "scratch-*.md" -o -name "HACKERONE_HACKER_LIMITATIONS.md" -o -name "ZERODAYBUDDY_TEST_REPORT.md" -o -name "create_manual_project.sql" -o -name "test_server.py"` returns empty.
- `ls docs/archive/` shows the moved files.
- `git status` shows the moves staged correctly.

---

### U5. Stabilize CI infrastructure (Go 1.25 + lint pinning + lint warning fixes)

**Goal:** Turn the chronic-red `lint` and `security` CI checks green and reproducible. Future PRs ride on a stable baseline so signal quality stays high.

**Requirements:** T1-5 (plan-time addition; see D6).

**Dependencies:** None. Independent of U1-U4 but lands in the same PR.

**Files:**
- `go.mod` (modify): bump `go 1.24.0` → `go 1.25.0`
- `go.sum` (regenerate via `go mod tidy`)
- `.github/workflows/ci.yml` (modify): bump `go-version` matrix and lint job to `1.25`; pin `golangci-lint-action` to a specific version
- `.golangci.yml` (modify): add `unusedwrite` to `linters-settings.govet.disable`
- `pkg/utils/utils.go` (modify): replace `io/ioutil` import and call sites with `io` and `os` equivalents
- `internal/core/errors_test.go` (modify): remove the dead `cmd = fmt.Sprintf(...)` line at the ineffassign site
- `README.md` (modify, if present): update Go version requirement to 1.25 if it's documented

**Approach:**

The work splits into two layers — infrastructure (Go version + lint config) and source-code fixes. Recommended ordering:

1. **Go version bump.** Edit `go.mod` line 3 from `go 1.24.0` to `go 1.25.0`. Edit `.github/workflows/ci.yml` to change `go-version: [ '1.24' ]` (test job matrix) and `go-version: '1.24'` (lint job and security job) to `'1.25'`. Run `go mod tidy` locally and commit the resulting `go.sum` changes.
   - Treat any major-version dep updates triggered by `go mod tidy` as execution-time discovery — diff `go.sum` carefully and revert any unintended bumps to keep the PR scope tight.
2. **Pin golangci-lint version.** In `.github/workflows/ci.yml`, change the lint job's `version: latest` to `version: <pinned-stable>`. Implementer should check the [golangci-lint releases](https://github.com/golangci/golangci-lint/releases) page at execution time and pick the current stable patch (e.g., `v1.64.x` or whatever supersedes it). Document the pin in the workflow file with a comment referencing this plan.
3. **Disable `unusedwrite`.** In `.golangci.yml`, under `linters-settings.govet.disable`, add `unusedwrite` next to the existing `fieldalignment`. Add a one-line comment: `# unusedwrite is noisy on test fixtures (struct literals set all fields for shape documentation)`.
4. **Replace `io/ioutil`.** In `pkg/utils/utils.go`, remove the `"io/ioutil"` import. Replace each call site mechanically: `ioutil.ReadAll` → `io.ReadAll`, `ioutil.ReadFile` → `os.ReadFile`, `ioutil.WriteFile` → `os.WriteFile`, `ioutil.TempFile` → `os.CreateTemp`, `ioutil.TempDir` → `os.MkdirTemp`, `ioutil.NopCloser` → `io.NopCloser`. Add `"io"` and/or `"os"` imports as needed (probably both already imported). Verify no other files in the repo import `io/ioutil` via `grep -rn "io/ioutil"`.
5. **Delete dead `cmd` assignment in errors_test.go.** Line 164 currently reads (paraphrased) `cmd = fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))`. The variable `cmd` is computed at lines 162-163 and the result on line 164 is never read. Just delete the ineffassign line. Verify by reading the surrounding test logic — if removing the line breaks something subtle, reconsider; the ineffassign warning is the canonical signal that it's dead.
6. **Update README.md if it specifies Go version.** A grep of `README.md` for `go 1.24` or "Go 1.24" should reveal any installation instructions to update.

**Patterns to follow:**
- For `io/ioutil` migration, the official Go `io/ioutil` package documentation lists the canonical replacement for each function: https://pkg.go.dev/io/ioutil
- For golangci-lint version selection, prefer the latest release that has been out for at least 1-2 weeks (avoids regressions in fresh releases).
- The existing CI workflow uses `actions/setup-go@v5` and `actions/cache@v4` — leave those at current versions; only the `go-version` value changes.

**Test scenarios:**
- **Build under Go 1.25.** `go build ./...` returns clean; no deprecation warnings or compile errors.
- **Test suite under Go 1.25.** `go test ./... -count=1 -race` — all 20 packages green. Particular attention to packages that exercised stdlib paths affected by the upstream changes (net/http handlers, crypto/tls TLS handshakes, net/url parsing) — verify no behavior regressions.
- **Lint at pinned version.** `golangci-lint run --timeout=3m` returns zero issues. Specifically confirm: no `unusedwrite` warnings (analyzer disabled), no `io/ioutil` deprecation warnings (import removed), no `ineffassign` warning at `internal/core/errors_test.go:164` (line removed).
- **govulncheck under Go 1.25.** `govulncheck ./...` returns zero calls into vulnerable Go stdlib (the 7 reported CVEs all have fixes in 1.25.x).
- **CI on the PR.** All checks green after push: `test (1.25)`, `lint`, `security`, `Analyze (actions)`, `Analyze (go)`, `CodeQL`. (`CodeRabbit` may take longer.)

**Verification:**
- All 5 test scenarios above pass.
- The PR's `gh pr checks` returns no `fail` rows.

---

## System-Wide Impact

| Surface | Before | After |
|---|---|---|
| CI merge gate | Evergreen `lint` + `security` red, advisory only | All checks green; merge gate trustworthy |
| Local Go requirement | 1.24.x | 1.25.x — README needs update if it documents version |
| Lint reproducibility | `version: latest` — moving target | Pinned to specific version |
| Documentation reliability | CLAUDE.md/TODO.md/CHANGELOG.md out of date | Trustworthy reference for future contributors and agents |
| Repo root cleanliness | 9 session artifacts | Canonical project files only |

**Affected parties:**
- **Future agent sessions** reading CLAUDE.md — get accurate codebase model
- **Future contributors** browsing the repo — see clean root and trustworthy docs
- **Local developers** — need to install Go 1.25 if currently on 1.24
- **CI consumers** — get reliable green signal as merge gate

---

## Scope Boundaries

**In scope:**
- All files listed in U1-U5 above.

### Deferred to Follow-Up Work

- **Audit for other deprecated stdlib usage beyond `io/ioutil`** — once `golangci-lint` is pinned and runs cleanly, future runs may surface other deprecations. Address as they appear in subsequent PRs rather than chasing them now.
- **Adopt Go 1.22+ range-over-int and range-over-func features** where they simplify code — the Go bump enables them but using them is a separate refactor concern.
- **`gosec` rule customization** — `gosec` is pinned at `v2.23.0` and currently passes. Custom rules out of scope unless it starts failing.
- **Splitting `TODO.md` into per-tier files** — possible future organization improvement, but adds maintenance burden. Out of scope.
- **Backport T1-5 into the brainstorm doc** — see D6.

### Not chasing

- Tier 2 (web router wiring), Tier 3 (manual project mode), Tier 4 (polish) — separate plans per the brainstorm sequence.
- Bumping any non-Go dependency for reasons other than what `go mod tidy` does automatically.

---

## Open Questions

1. **Will `go mod tidy` after the Go bump pull major version updates?** Most deps in `go.mod` are version-pinned, so unlikely — but worth diffing `go.sum` carefully and reverting any unintended major bumps to keep the PR scope tight.
2. **Does `README.md` document a Go version?** Need to grep at execution time and update if so. Listed under U5 step 6.
3. **Pinned golangci-lint version — exact patch?** The implementer picks the current stable at execution time. Plan recommends `v1.64.x` or whatever has superseded it.

---

## Verification Gate

The plan is complete when **all** of the following pass:

```text
1. go build ./...                            # clean under Go 1.25
2. go test ./... -count=1 -race              # all packages green
3. golangci-lint run --timeout=3m            # zero issues at pinned version
4. govulncheck ./...                         # zero calls into vulnerable stdlib
5. find . -maxdepth 1 \( -name "scratch-*" -o -name "test_server.py" -o -name "create_manual_project.sql" -o -name "HACKERONE_HACKER_LIMITATIONS.md" -o -name "ZERODAYBUDDY_TEST_REPORT.md" \)  # empty
6. grep -i "scan service is.*stub\|currently stub" CLAUDE.md   # empty
7. CI on PR: all checks green (test/lint/security/Analyze/CodeQL)
```

---

## Suggested Commit Boundary

Five commits in one PR, one per unit:

1. `docs: refresh CLAUDE.md to match current codebase capability (T1-1)`
2. `docs: refresh TODO.md and remove completed items (T1-2)`
3. `docs: populate CHANGELOG.md [Unreleased] with Phases 1-4 and recent fixes (T1-3)`
4. `chore: archive scratch files and one-off artifacts to docs/archive/ (T1-4)`
5. `chore(ci): bump Go to 1.25, pin golangci-lint, fix io/ioutil and ineffassign (T1-5)`

Doc-only commits (1-3) can be squashed into one `docs:` commit if the implementer prefers, but separation matches the brainstorm's tier-item granularity and makes `git log` traceable to the punch list.
