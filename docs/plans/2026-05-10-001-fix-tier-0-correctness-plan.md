---
title: "fix: Tier 0 correctness — complete validation security fix and clean up :memory: test bug"
date: 2026-05-10
type: fix
depth: lightweight
status: active
origin: docs/brainstorms/codebase-punch-list-requirements.md
related_units: U1, U2
---

# Tier 0 Correctness Plan

## Summary

Land all three Tier 0 punch-list items (T0-1, T0-2, T0-3 from the origin brainstorm) in a single session that ends with `go test ./...` green and no `:memory:` directories on disk.

The plan collapses what the brainstorm framed as three independent items into **two implementation units**:

| Unit | Origin items | Why grouped |
|---|---|---|
| U1 | T0-1 + T0-2 | The broken test file *is* the in-progress security fix for the strings.Contains scope-bypass. Implementing the missing functions both unblocks the build and lands the security fix — they cannot meaningfully be separated. |
| U2 | T0-3 | Fix the test config bug that creates literal `:memory:/` directories on disk. Independent root cause (`internal/core/app_test.go:18`), independent file surface. |

---

## Problem Frame

Three independent correctness defects identified in the brainstorm-time audit:

1. **`pkg/validation/project_test.go` fails to build** — the (untracked) test file references `matchesDomain` and `extractHost`, neither of which exists in the package. Result: `go test ./...` fails with `undefined:` errors before any assertions run, blocking CI signal for the whole repo.

2. **`pkg/validation/project.go:48` `ProjectScope`** uses `strings.Contains(target, asset.Value)` for in-scope checks. This is exploitable in principle: a target of `evil-example.com` matches an in-scope asset of `example.com`. Currently *unreachable* from production code (`validation.ProjectScope` has zero non-test callers — confirmed by `grep -rn "validation\.ProjectScope\|\.ProjectScope("`), but the planned web-handler work in Tier 2 of the brainstorm will need exactly this kind of pre-fetch URL-vs-scope validation, so quietly deleting the function leaves a hole that the next handler implementer will refill from scratch.

3. **`internal/core/:memory:/` and `cmd/zerodaybuddy/:memory:/` directories** exist on disk because `internal/core/app_test.go:18` sets `DataDir: ":memory:"`, treating it as a SQLite in-memory sentinel. But `internal/storage/store.go:90 NewStore()` does `os.MkdirAll(dataDir, 0700)` first, then `filepath.Join(dataDir, "zerodaybuddy.db")` — so a literal directory `:memory:/` gets created at whatever cwd the test runs from, and the database is opened at `:memory:/zerodaybuddy.db` (a real on-disk file, not in-memory). Cosmetic but signals a quietly-failing test contract.

---

## Requirements Trace

From `docs/brainstorms/codebase-punch-list-requirements.md`:

- **T0-1** (Fix `pkg/validation/project_test.go` build break) → **U1**
- **T0-2** (Resolve duplicate scope-checking implementations) → **U1** (with brainstorm-recommendation reversal — see Key Technical Decisions D1)
- **T0-3** (Clean up `:memory:` literal directories) → **U2**

Tier 0 success criterion from origin:

> `go test ./...` runs to completion with zero build failures (T0-1)
> `grep -rn "strings.Contains.*Value" pkg/` returns no scope-check results (T0-2)
> `find . -path "*/:memory:*"` returns nothing (T0-3)

All three are addressed by U1 + U2. See **Verification** below for the explicit gate.

---

## Key Technical Decisions

### D1. Complete the in-progress security fix instead of deleting `ProjectScope`

**Reverses the brainstorm's "delete it" recommendation.** Reading `pkg/validation/project_test.go` revealed the test file is not abandoned cruft — it is a deliberate, comprehensive security fix in progress:

- Tests cover the exact boundary bypass the original code allowed: `evil-example.com / example.com → false`, `notexample.com / example.com → false`, `example.com.evil.com / example.com → false`.
- Tests cover wildcard patterns (`*.example.com`).
- Tests cover the URL parsing path (`https://example.com:8443/path` → `example.com`).
- Tests cover the case where `ProjectScope` itself rejects bypass attempts at the public API.

Deleting `ProjectScope` and these tests would discard work and leave the next contributor (likely Tier 2's web handlers) to re-derive the same logic from scratch. Completing the fix is a smaller delta and produces a reusable, well-tested validation helper for future handler work.

**Boundary with `models.Scope.IsInScope`.** The two functions serve different layers and remain both useful:

| Function | Inputs | Caller layer | Use case |
|---|---|---|---|
| `models.Scope.IsInScope(assetType, value)` | already-loaded `Scope`, asset value | service layer (already has Project) | "is this URL in this in-memory project's scope?" |
| `validation.ProjectScope(ctx, store, projectName, target)` | name, target, store handle | handler / CLI layer (only has user input) | "given a project name, look it up and validate the user-provided target before doing real work" |

### D2. `:memory:` fix is a test-side correction, not a storage-layer behavior change

**Origin of the bug:** `internal/core/app_test.go:18 getTestConfig()` returns `DataDir: ":memory:"` — the developer assumed `:memory:` would route to SQLite's in-memory mode. But `internal/storage/store.go:90 NewStore()` treats `dataDir` as a filesystem path and does `os.MkdirAll(dataDir, 0700)` first.

**Fix chosen:** Change `getTestConfig()` to take `*testing.T` and use `t.TempDir()` for `DataDir`. This is the minimal-correct change and matches the pattern already used by `cmd/zerodaybuddy/test_helpers.go:createTestApp` (which uses `os.MkdirTemp("", "zerodaybuddy-test-*")`).

**Considered and deferred:** Adding defensive sentinel handling in `storage.NewStore` (detect `":memory:"` and route to `sqlx.Connect("sqlite", ":memory:")` directly). This would be a *better* contract — SQLite users reasonably expect that semantics — but it's a production-code behavior change beyond Tier 0 correctness scope. Routed to "Deferred to Follow-Up Work" below.

### D3. Single batched commit boundary

Both units are small, low-risk, and verified by the same `go test ./...` gate. Land both in one PR/commit (or two atomic commits within the same PR) to keep the Tier 0 punch-list closure visible as one unit of work.

---

## Implementation Units

### U1. Complete the validation security fix

**Goal:** Implement `matchesDomain` and `extractHost` in `pkg/validation/project.go`, refactor `ProjectScope` to use them, ensure `pkg/validation` test build passes and all tests in `project_test.go` pass.

**Requirements:** T0-1, T0-2 from origin.

**Dependencies:** None.

**Files:**
- `pkg/validation/project.go` (modify): add `matchesDomain(targetHost, scopeDomain string) bool` and `extractHost(rawURL string) string`; refactor `ProjectScope` to call them
- `pkg/validation/project_test.go` (already exists, untracked): add to git; do not modify the test cases (they are the spec)

**Approach:**
- `extractHost(rawURL)` parses `rawURL` via `net/url.Parse` and returns the hostname portion (port-stripped). Returns empty string when parse fails or host is empty. This matches the `TestExtractHost` cases including `"not a url" → ""` (since `url.Parse` of an unstructured string yields no host).
- `matchesDomain(targetHost, scopeDomain)` performs case-insensitive matching with three accept paths: (1) exact match (`targetHost == scopeDomain`); (2) wildcard scope (`*.example.com`) matching `example.com` and any subdomain; (3) plain scope domain matching subdomains via dot-anchored suffix check (`strings.HasSuffix(target, "."+scope)`). Empty `targetHost` or empty `scopeDomain` returns false.
- The dot-anchored suffix check is the security-critical detail: `strings.HasSuffix("evil-example.com", "example.com")` is true, but `strings.HasSuffix("evil-example.com", ".example.com")` is false. The test cases in `TestMatchesDomain` and `TestProjectScope_DomainBoundary` enforce this boundary.
- `ProjectScope` is refactored to: (a) load the project as before; (b) for URL targets, `extractHost` then walk in-scope assets calling `matchesDomain` for `Domain` and `URL` types (the URL case `extractHost`s the asset value first); (c) for non-URL targets, walk in-scope assets matching exactly. Replace the existing `strings.Contains` line.
- Keep `ProjectExists` and `isURL` unchanged — both have passing tests.

**Patterns to follow:**
- The fix mirrors the pattern already established in `pkg/models/models.go:296 matchAsset()` and `pkg/models/models.go:338 isSubdomain()`. Worth scanning that file for conformance, but do *not* import models functions into validation — the layering should stay one-way (validation is a leaf, models is a dependency of validation, not the other way).
- Error messages on failed scope checks should mirror the existing format (`"target '%s' is not in project scope"`).

**Test scenarios** (the test file already enumerates these; they are the specification):
- **`TestMatchesDomain`:** exact, case-insensitive, subdomain, deep subdomain, boundary-bypass blocked (`evil-example.com`, `notexample.com`, `example.com.evil.com`), wildcard exact and subdomain matches, wildcard rejecting unrelated and boundary-bypass attempts, empty target, empty scope, completely unrelated domain.
- **`TestExtractHost`:** simple URL, URL with port (port stripped), URL with path, URL with subdomain, invalid URL (returns empty string).
- **`TestProjectScope_DomainBoundary`:** exact domain match in URL, subdomain match in URL, exact URL-asset match; rejects boundary bypass (`evil-example.com`), prefix bypass (`notexample.com`), unrelated domain.
- **`TestProjectScope_NonURL`:** exact non-URL match, no match.
- **`TestIsURL`:** https/http accepted; bare domain, ftp, short string, empty rejected.
- **`TestProjectExists`:** existing project ok; not-found error; invalid name (empty, special chars) rejected.

**Verification:**
- `go build ./pkg/validation/...` succeeds.
- `go test ./pkg/validation/... -count=1 -v` passes all subtests.
- `grep -n "strings.Contains" pkg/validation/project.go` returns nothing.

---

### U2. Fix `:memory:` test config bug and clean up stray directories

**Goal:** Eliminate the literal `:memory:/` directories that get created when `internal/core` tests run, by fixing the test config to use `t.TempDir()` instead of the misinterpreted SQLite sentinel.

**Requirements:** T0-3 from origin.

**Dependencies:** None.

**Files:**
- `internal/core/app_test.go` (modify): change `getTestConfig()` signature to `func getTestConfig(t *testing.T) *config.Config`; replace `DataDir: ":memory:"` with `DataDir: t.TempDir()`; update all call sites in this file to pass `t`
- `.gitignore` (modify): add `:memory:/` entry as defense-in-depth so any future regression doesn't pollute commits
- `internal/core/:memory:/` (delete): `rm -rf` the stray directory and its contents (`zerodaybuddy.db`, `.db-shm`, `.db-wal`)
- `cmd/zerodaybuddy/:memory:/` (delete): `rm -rf` the stray empty directory

**Approach:**
- `getTestConfig` currently has no `*testing.T` parameter. Adding it is a mechanical signature change — every caller in `internal/core/app_test.go` already has `t` in scope (they're `func TestXxx(t *testing.T)`). Update all `cfg := getTestConfig()` call sites to `cfg := getTestConfig(t)`.
- Three call sites in the same file already override `cfg.DataDir = t.TempDir()` after calling `getTestConfig()` (lines 196, 220, 240). After the fix they can keep that override harmlessly — `t.TempDir()` in `getTestConfig` and again at the call site just produces two temp dirs, only the second one is used. Leave the override calls in place to preserve test intent (the override-callers explicitly want their own scoped tempdir for the body of the test).
- `cmd/zerodaybuddy/test_helpers.go:createTestApp` already uses `os.MkdirTemp` correctly. No changes needed there. The stray `cmd/zerodaybuddy/:memory:/` directory was created earlier by a different code path (now historical) and is empty — it just needs deletion.
- The `.gitignore` addition (`:memory:/`) prevents future accidental commits if this regression returns. It's a one-line defensive measure.

**Patterns to follow:**
- `cmd/zerodaybuddy/test_helpers.go:12 createTestApp(t *testing.T)` is the established pattern for test helpers that need temp data dirs.
- `internal/auth/service_test.go:16 sqlx.Connect("sqlite", ":memory:")` is the *correct* way to use SQLite's in-memory sentinel — directly as a DSN, not via the `DataDir → MkdirAll → filepath.Join` path.

**Test scenarios:**
- After the change, `go test ./internal/core/... -count=1` runs without creating any `:memory:` directories anywhere on disk.
- All existing tests in `internal/core/app_test.go` still pass.
- `go test ./...` does not create new `:memory:/` artifacts (verified by `find . -path "*/:memory:*"` after a full test run).

Test expectation: none for the `.gitignore` change (configuration only, no behavior change).

**Verification:**
- `go test ./internal/core/... -count=1` passes.
- `find /Users/nconsolo/claude-code/zerodaybuddy -path "*/:memory:*"` returns nothing.
- `git status` shows no untracked `:memory:` directories.

---

## Scope Boundaries

**In scope:**
- Implementing `matchesDomain` and `extractHost` in `pkg/validation/project.go`.
- Refactoring `ProjectScope` to use the new functions.
- Adding `pkg/validation/project_test.go` to git (it currently shows as untracked).
- Fixing `internal/core/app_test.go:getTestConfig()` to take `*testing.T` and use `t.TempDir()`.
- Deleting the stray `:memory:/` directories.
- Adding `:memory:/` to `.gitignore`.

### Deferred to Follow-Up Work

- **Defensive `:memory:` sentinel in `storage.NewStore`.** Detect when `dataDir == ":memory:"` and route to `sqlx.Connect("sqlite", ":memory:")` directly without `MkdirAll`. Better contract, matches SQLite convention, but is a production-code behavior change beyond Tier 0 scope. Worth a separate plan if/when an in-memory test mode for the storage layer is genuinely needed.
- **Wiring `validation.ProjectScope` into production callers.** Currently dead code. Will become live when Tier 2 web-handler work (T2-1, T2-2 in the brainstorm) lands and accepts user-submitted URLs. That's a separate plan.
- **Auditing for other `:memory:`-style magic-string assumptions.** The `:memory:` bug is a single instance; there might be other places where developers assumed library sentinels work through wrapping layers. Out of scope for Tier 0; could become a Tier 1 hygiene pass.

### Not chasing

- All Tier 1, 2, 3, 4 items from the origin brainstorm — those are sequenced for later sessions per the suggested-sequence table in `docs/brainstorms/codebase-punch-list-requirements.md`.
- Refactoring `models.IsInScope` or `models.matchAsset` — they pass their tests and serve a different layer (see D1). Out of scope.

---

## Open Questions

None blocking. The reversal in D1 is a strong recommendation that the user already implicitly endorsed by ranking correctness-first; if they disagree, U1 can be re-scoped to "delete `ProjectScope` and its test file" without changing U2.

---

## Verification Gate (end-of-plan)

The plan is complete when **all** of the following return clean:

```text
1. go build ./...                                                      # from repo root
2. go test ./... -count=1                                              # all packages, all tests
3. grep -rn "strings.Contains" pkg/validation/project.go               # → empty
4. find . -path "*/:memory:*" -not -path "*/.git/*"                    # → empty
5. git diff --stat                                                      # touches expected files only
```

If any of (1)-(4) fail, the corresponding unit is incomplete. Step (5) is a sanity check that the diff stays scoped.

---

## Suggested Commit Boundary

Two atomic commits, both in the same PR:

1. `fix(validation): complete domain-boundary scope check (T0-1, T0-2)` — covers U1
2. `fix(test): use t.TempDir() in getTestConfig to stop creating :memory: dirs (T0-3)` — covers U2

Or one squashed commit if the PR is short-lived. Either is fine — D3 just requires that both units land together so Tier 0 closes as a single unit of progress against the brainstorm.
