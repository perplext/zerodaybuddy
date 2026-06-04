---
title: "feat: Tier 3 surface expansion — manual project mode, scope file schema, HackerOne hacker-account UX"
date: 2026-06-03
type: feat
depth: standard
status: completed
origin: docs/brainstorms/codebase-punch-list-requirements.md
related_units: U1, U2, U3, U4, U5
deepened: 2026-06-03
---

# Tier 3 — Surface Expansion (T3-1, T3-2, T3-3)

## Summary

Open ZeroDayBuddy to users who can't (or don't want to) drive everything through a bug-bounty platform API. Three threads: a **scope file schema + loader/validator** (T3-2) that parses YAML/JSON into `models.Scope` using the existing 9-value `AssetType` enum; a **manual project mode** (T3-1) that lets `CreateProject` build a project from a scope document instead of a platform fetch, exposed on both the CLI (`project create --manual --scope-file`) and the existing web create endpoint; and a **HackerOne hacker-account clarification** (T3-3) that turns the existing 401 hint into a first-class, actionable error pointing at manual mode.

The architectural seam is already half-built: `validation.ValidPlatforms` already contains `"manual"`, the web `create` handler already accepts an inline `Scope`, and `matchAsset` already handles wildcards and CIDR via the value string. The work is to fill the gaps between those facts — a shared scope validator, a `CreateProject` fork, CLI flags, and sharper error messaging — not to build new subsystems.

---

## Problem Frame

`App.CreateProject` (`internal/core/app.go:191`) only knows one path: look up `a.platforms[platformName]` (populated with `hackerone` and `bugcrowd` only) and call `GetProgram`. A user passing `--platform manual` passes `validation.Platform` (which already allows `"manual"`) but then hits `unknown platform: manual` at the map lookup. There is no way to create a project from a hand-authored scope.

This blocks the individual-hacker and arbitrary-security-work personas documented in `docs/archive/HACKERONE_HACKER_LIMITATIONS.md` and `docs/archive/ZERODAYBUDDY_TEST_REPORT.md`: HackerOne's full program API is org-tier, so a solo hacker with a hacker-tier token cannot pull scope, and has no fallback. The web `create` handler (`internal/web/handlers/projects.go:90`) already stores an inline `req.Scope` but never validates its contents — so today it would silently persist garbage asset types.

See origin: `docs/brainstorms/codebase-punch-list-requirements.md` §3 Tier 3, and Open Question #3 (individual-hacker persona), which the decision to build Tier 3 answers affirmatively.

---

## Requirements

- R1. A scope file (YAML or JSON) with `in_scope[]` / `out_of_scope[]` parses into `models.Scope`, with every asset validated against the existing `AssetType` enum. (origin T3-2)
- R2. `zerodaybuddy project create --manual --name X --scope-file scope.yaml` creates a working project whose scope is loaded from the file. (origin T3-1)
- R3. `App.CreateProject` is factored to accept either a `(platform, programHandle)` source or a manual scope-document source, without breaking the existing platform path. (origin T3-1)
- R4. The web create endpoint validates an inline manual scope through the same validator the CLI uses, rejecting invalid asset types/values rather than persisting them. (origin T3-1, decision: CLI + web)
- R5. A hacker-tier HackerOne token produces a clear, actionable error that points the user at manual mode, rather than a raw 401 dump. (origin T3-3)

**Origin actors:** individual hacker (hacker-tier token, no org API), security researcher (arbitrary scope, no platform).
**Origin flows:** create-project-from-scope-file (CLI), create-project-from-scope-doc (web), platform-token-tier-detection (HackerOne).

---

## Scope Boundaries

- No widening of the `AssetType` enum — wildcards/CIDR are already matched within the value string under `domain`/`ip` (decided in planning; see origin T3-2's deferral note).
- No new asset-taxonomy alignment work beyond the existing 9 values (HackerOne/Bugcrowd taxonomy mapping stays as-is).
- No full hacker-tier HackerOne API client — T3-3 is clarification + error messaging only, per origin ("not a full alternate API client").
- No scope-file editing UI in the dashboard — web manual creation accepts a scope document in the request body (T2-2's handler), not a file-upload widget.

### Deferred to Follow-Up Work

- Scope-file upload widget / paste-box in the dashboard UI: future iteration (Tier 4 web polish).
- `project update --scope-file` (re-import scope into an existing project): follow-up; this plan covers creation only.
- Optional hacker-side HackerOne endpoints (e.g. `/v1/hackers/me`): follow-up if demand surfaces (origin T3-3 "Optionally").

---

## Context & Research

### Relevant Code and Patterns

- `internal/core/app.go:191` — `CreateProject(ctx, platformName, programHandle)`; the fork point. `a.platforms` map populated at `app.go:87-88` (hackerone, bugcrowd only).
- `pkg/models/models.go:13-23` — `AssetType` enum (9 values). `Scope`/`Asset` structs at `:98-112`. `Scope.IsInScope` at `:115`; `matchAsset` at `:296` already handles exact/wildcard (`*.`)/CIDR (`/`).
- `pkg/validation/validation.go:40` — `ValidPlatforms` already includes `"manual"`. `Platform()` at `:49`. `FilePath()` at `:119` for `--scope-file` path safety.
- `cmd/zerodaybuddy/main.go:118-149` — `createProjectCreateCommand`: cobra command with `--platform`/`--program`, `MarkFlagRequired`. Pattern to extend with `--manual`/`--scope-file`.
- `internal/web/handlers/projects.go:90-163` — `create`: already decodes `req.Scope` and stores it; already calls `validation.Platform(req.Platform)`. Gap: no scope-content validation.
- `internal/platform/hackerone.go` — `fetchProgramsPage` already emits a 401 hint about individual hacker accounts; `GetProgram`/`FetchScope` are the per-program paths to harden for T3-3. **Note:** all three paths currently interpolate `string(body)` into the 401 error — the hardening must drop that, not copy it (see U5).

### Institutional Learnings

- `docs/solutions/` does not exist yet — no prior learnings to carry forward. (Worth seeding one post-implementation on the scope-file format.)
- Storage tests use a shared-cache SQLite DSN, not `:memory:` (recent fix, commit `bc23198`) — manual-mode integration tests must follow that pattern.

### External References

- HackerOne API is org-tier for program/scope endpoints; hacker-tier tokens 401 on them. This is the documented constraint motivating manual mode (origin + `docs/archive/HACKERONE_HACKER_LIMITATIONS.md`).

---

## Key Technical Decisions

- **Reuse the existing 9-value `AssetType` enum** (user decision): the scope loader validates each asset's `type` against the enum and rejects unknown values. Wildcard/CIDR need no new types — they live in the value. Keeps the change off `models.go`'s *matching* logic (`matchAsset`/`IsInScope`), DB serialization, and platform mappers. (It does add struct tags to `Scope`/`Asset` — see next decision.)
- **Add `yaml` struct tags to `models.Scope`/`models.Asset`** (fixes a verified parse bug): these structs currently carry only `json` tags. `gopkg.in/yaml.v3` lowercases Go field names by default, so a scope file using `in_scope:` / `out_of_scope:` / `smart_contract` would unmarshal to **empty slices** and then fail validation — the headline YAML path would silently break. Add `yaml:"in_scope"` etc. to the two structs. This is a tag-only change; it does **not** touch matching logic or DB serialization. (The JSON path is unaffected — `encoding/json` already honors the `json` tags.)
- **One shared validator, two entry points**: a `models.Scope` validator (`ValidateScope`) is the single source of truth. The CLI file loader parses YAML/JSON → `models.Scope` → `ValidateScope`; the web handler runs `ValidateScope` on the decoded inline scope. Prevents the CLI and web paths from drifting.
- **`gopkg.in/yaml.v3` is currently an indirect dependency** (verified): `pkg/config` uses `spf13/viper` with `mapstructure` tags, **not** yaml.v3 directly, so there is no existing yaml-usage pattern to copy. Importing yaml.v3 in `pkg/models` promotes it to a direct `require` in `go.mod` (a `go mod tidy`, not a new download).
- **Format detection by extension with content fallback**: `.yaml`/`.yml` → YAML, `.json` → JSON; unknown extension attempts YAML (a superset that also parses JSON) so users aren't forced into an extension. Single loader function, no separate APIs. Use yaml.v3's strict/known-fields decoding so unexpected keys are rejected rather than silently dropped.
- **Fork `CreateProject` via a new `CreateManualProject(ctx, name, scope, opts)` rather than overloading the existing signature**: keeps the platform path byte-for-byte unchanged (R3 "without breaking the existing path"), and gives the CLI/web a clean call target. The existing `CreateProject` stays as the platform path.
- **Web manual-create shares the default logic, not just validation** (closes a drift risk): the existing web handler defaults `Type` to `bug-bounty` for all projects, but manual mode should default to `research` (matching U2/U3). To avoid two divergent default-application sites, extract the manual-project construction (defaults + `ValidateScope`) into one helper both U2 and U4 call, or have U4 delegate to it. A parity test asserts CLI-created and web-created manual projects get identical defaults.
- **Internal-range scope values are allowed but rely on the scan-service SSRF filter as the safety net** (S4 decision — see Open Questions): `ValidateScope` does **not** hard-reject RFC-1918/loopback/link-local values, because internal CIDRs are legitimate scope for `pentest`/`research` projects (and the examples use `10.0.0.0/8`). Authorization-to-be-in-scope is separate from permission-to-be-scanned: the scan service already blocks RFC-1918/cloud-metadata/IPv6-ULA regardless of scope. This keeps scope expressive while the existing SSRF filter remains the enforcement boundary.
- **T3-3 is messaging, not a client**: detect the hacker-tier signal (401 on a program/scope fetch) and wrap it in a typed, actionable error recommending `--manual`. The error message is built from the HTTP status code and a canned string only — the raw response body is **never** interpolated into the user-facing error (it may be logged at DEBUG). No new HTTP paths.

---

## Open Questions

### Resolved During Planning

- Widen `AssetType` enum? → No. Wildcards/CIDR already handled by `matchAsset` via value patterns (verified at `pkg/models/models.go:296`).
- Web exposure for manual mode? → Yes, add scope-content validation to the existing web `create` handler (user decision).
- YAML, JSON, or both? → Both, via one loader with extension detection (YAML parser handles both). **Requires `yaml` struct tags on `Scope`/`Asset`** — verified that without them yaml.v3 parses `in_scope:` to empty.
- Should `ValidateScope` reject internal/RFC-1918 IP ranges? → **No, allow them.** Internal CIDRs are valid scope for `pentest`/`research` projects; the scan service's existing SSRF filter (RFC-1918 / cloud-metadata / IPv6-ULA) is the enforcement boundary, not scope validation. Being in-scope ≠ being scannable. (Confirm with maintainer; flagged by security review.)
- Run `ValidateScope` only for manual projects, or whenever a scope is supplied? → **Whenever `in_scope` is non-empty, regardless of platform** — gating on `platform=="manual"` left a bypass (`platform=hackerone` + inline scope skips validation).

### Deferred to Implementation

- Exact validator function name/signature (`ValidateScope` vs `Scope.Validate` method) — settle when touching `pkg/models`.
- Whether `CreateManualProject` should accept a `ProjectType` override (research/pentest) now or default to `research` — decide when wiring the CLI flag; default `research` is the natural fit for manual mode.
- The precise typed-error shape for T3-3 (new sentinel in `pkg/errors` vs `WithContext`) — match whatever `pkgerrors` idiom the surrounding code already uses.

---

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```text
scope.yaml / scope.json ──┐
                          ├─(CLI: LoadScopeFile)─► models.Scope ─┐
inline JSON scope (web) ──┘                                      ├─► ValidateScope ──► CreateManualProject ──► store.CreateProject
                                                                 │       (rejects bad type/value)
HackerOne GetProgram 401 ──► typed "use --manual" error ─────────┘  (T3-3: points back to this path)
```

Decision matrix for create paths:

| Input | Platform flag | Source | Validator |
|---|---|---|---|
| `--platform hackerone --program acme` | hackerone/bugcrowd | `GetProgram` API fetch | platform-supplied scope (trusted) |
| `--manual --scope-file s.yaml` | manual | `LoadScopeFile` | `ValidateScope` |
| web POST `{platform:"manual", scope:{...}}` | manual | inline body | `ValidateScope` |

---

## Implementation Units

### U1. Scope file schema, loader, and validator (T3-2 core)

**Goal:** Define the scope-file format and a single shared validator; provide a loader that parses YAML/JSON into `models.Scope`. This is the dependency both create paths build on.

**Requirements:** R1

**Dependencies:** None

**Files:**
- Create: `pkg/models/scopefile.go` (loader `LoadScopeFile(path) (*Scope, error)` + `ValidateScope(*Scope) error` + `IsValidAssetType(AssetType) bool`)
- Modify: `pkg/models/models.go` — add `yaml:"..."` struct tags to `Scope` (`in_scope`, `out_of_scope`) and `Asset` (`type`, `value`, `description`, `instructions`, `tags`, `attributes`). Tag-only; no logic change.
- Create: `examples/scope.yaml` (documented example with in/out of scope, wildcard, CIDR)
- Create: `examples/scope.json` (JSON equivalent, proves both formats parse)
- Test: `pkg/models/scopefile_test.go`
- Modify: `go.mod` / `go.sum` via `go mod tidy` — promotes `gopkg.in/yaml.v3` from indirect to a direct require (already in the module graph; no new download).

**Approach:**
- **Struct tags first:** without `yaml` tags, yaml.v3 lowercases field names and `in_scope:` parses to an empty `InScope` (verified). Add the tags before writing the loader, or the YAML happy path is dead on arrival.
- `ValidateScope`: non-empty `in_scope`, every `Asset.Type` ∈ enum (`IsValidAssetType`), every `Asset.Value` non-empty; for `domain`/`ip` values optionally sanity-check shape but do not over-constrain (wildcards/CIDR are valid values). Does **not** reject internal/RFC-1918 ranges (see Key Technical Decisions — scan-service SSRF filter is the enforcement boundary).
- `LoadScopeFile`: **stat and reject files over a size cap (e.g. 1 MB) before reading** (guards against OOM / YAML alias-bomb expansion); detect format by extension (`.json` → JSON, else YAML which also parses JSON); decode with **known-fields/strict mode** so unexpected keys error rather than silently drop; then `ValidateScope`. Surface clear errors naming the asset index/field that failed.

**Patterns to follow:** `pkg/utils/json.go` for the project's custom JSON conventions; error wrapping style in `pkg/errors`. (Note: `pkg/config` uses viper/mapstructure, **not** yaml.v3 — it is not a yaml pattern to copy.)

**Test scenarios:**
- Happy path: valid YAML with domain + `*.example.com` wildcard + `10.0.0.0/8` CIDR + url asset → `Scope` with correct counts; `IsInScope(AssetTypeIP, <ip-in-CIDR>)` and `IsInScope(AssetTypeDomain, <subdomain>)` both true. Covers AE for R1. **This test specifically guards the yaml-tag bug — it must use a YAML file, not JSON.**
- Happy path: equivalent JSON file parses to the same `Scope` (counts identical to the YAML case).
- Edge case: extensionless file containing YAML → parses (fallback path).
- Edge case: empty `out_of_scope` is allowed; empty/missing `in_scope` is rejected.
- Error path: unknown asset type (`"web"`) → error naming the offending value and the allowed set.
- Error path: unexpected/misspelled key (e.g. `in_scopes:`) → strict-decode error, not a silent empty scope.
- Error path: asset with empty `value` → error naming the index/field.
- Error path: file exceeding the size cap → rejected before unmarshal.
- Error path: malformed YAML/JSON → wrapped parse error, not a panic.
- Error path: nonexistent file path → clear not-found error.

**Verification:** `go test ./pkg/models/...` green; a YAML example file round-trips to a non-empty scope (proving tags work); an invalid type and an oversized file are both rejected with clear messages.

---

### U2. Factor `App.CreateProject` for manual mode (T3-1 core)

**Goal:** Add `App.CreateManualProject` that builds and persists a project from a validated scope document, leaving the existing platform path unchanged.

**Requirements:** R3

**Dependencies:** U1

**Files:**
- Modify: `internal/core/app.go` (add `CreateManualProject(ctx, name string, scope models.Scope, opts ...)`; keep `CreateProject` as-is)
- Test: `internal/core/app_test.go` (or the existing core test file for project creation)

**Approach:**
- `CreateManualProject` runs `ensureInitialized`, calls `models.ValidateScope`, constructs the project, persists via `a.store.CreateProject`, and prints the same scope summary the platform path prints.
- **Centralize the manual-project defaults so the web path (U4) can reuse them** rather than re-implementing `Type: research`. Put the construction (defaults `Type:research`, `Status:active`, `Handle` derived from `Name`, `Platform:manual`) + `ValidateScope` in one place both U2 and U4 call. This is the structural fix for the CLI/web default-drift risk.
- Derive `Handle` from `Name` when none supplied (mirror web handler `req.Handle == "" → req.Name`), passing through `validation.Handle`/`ProjectName`.
- Do not route manual mode through `a.platforms` — it has no client.

**Patterns to follow:** existing `CreateProject` body (`app.go:191-231`) for project construction, logging, and the scope-summary print; `pkgerrors` for wrapping.

**Test scenarios:**
- Happy path: valid scope → project persisted with `Platform=="manual"`, scope counts match, retrievable via `store.GetProjectByName`.
- Edge case: name with no handle → handle derived from name and valid.
- Error path: scope failing `ValidateScope` → error, nothing persisted (verify store has no project).
- Error path: duplicate project name → storage error surfaced (matches platform-path behavior).
- Integration: created manual project is usable by a downstream read (`ListProjects` shows it).

**Verification:** `go test ./internal/core/...` green; a manual project created in-test is found by name with manual platform and correct scope.

---

### U3. CLI `project create --manual --scope-file` wiring (T3-1)

**Goal:** Extend the CLI so manual mode is reachable; keep the platform flags working.

**Requirements:** R2

**Dependencies:** U1, U2

**Files:**
- Modify: `cmd/zerodaybuddy/main.go` (`createProjectCreateCommand`)
- Test: `cmd/zerodaybuddy/main_test.go` (or existing CLI test file)

**Approach:**
- Add `--manual` (bool), `--scope-file` (string), `--name` (string) flags alongside existing `--platform`/`--program`.
- Branch in `RunE`: if `--manual` (or `--platform manual`), require `--name` + `--scope-file`, validate the path, `LoadScopeFile`, then `app.CreateManualProject`. Else the existing platform branch (`--platform`+`--program` required).
- **Path safety is more than `validation.FilePath`:** `FilePath` only enforces a parent-exists check for paths outside cwd/home, so it accepts arbitrary absolute paths like `/etc/passwd` (verified at `pkg/validation/validation.go:146-152`). After `FilePath`, additionally require the resolved path to have an allowed extension (`.yaml`/`.yml`/`.json`). The size cap and strict decode live in `LoadScopeFile` (U1).
- Make `--platform`/`--program` no longer unconditionally required (they're required only for the platform branch); enforce per-branch requirements inside `RunE` with clear errors. Add a comment at the branch point noting requirements are now enforced manually (not via `MarkFlagRequired`), so a future platform-branch addition doesn't silently skip them.
- Optional `--type` flag (default `research`) validated against `validation.ValidProjectTypes`.

**Patterns to follow:** existing cobra flag/validation flow in the same function (`main.go:118-149`); `validation.FilePath` for path safety.

**Test scenarios:**
- Happy path: `--manual --name foo --scope-file <valid>` → calls `CreateManualProject`, exit 0. Covers AE for R2.
- Edge case: `--manual` without `--scope-file` → clear "scope-file required in manual mode" error, no project created.
- Edge case: `--manual` without `--name` → clear required-flag error.
- Error path: `--scope-file` pointing at a path-traversal / nonexistent file → rejected by `validation.FilePath` / loader.
- Happy path (regression): existing `--platform hackerone --program acme` path still validated and routed to `CreateProject` unchanged.
- Error path: neither manual nor platform flags → helpful usage error.

**Verification:** `go build ./cmd/...` succeeds; `go test ./cmd/...` green; manual and platform branches both exercised; success criterion `zerodaybuddy project create --manual --name foo --scope-file ex.yaml` produces a project (origin §8).

---

### U4. Web manual-project scope validation (T3-1, web exposure)

**Goal:** Make the existing web `create` handler validate an inline manual scope through the shared validator, so the dashboard/API can create manual projects safely.

**Requirements:** R4

**Dependencies:** U1

**Files:**
- Modify: `internal/web/handlers/projects.go` (`create`)
- Test: `internal/web/handlers/projects_test.go`

**Approach:**
- After decoding `req` and validating platform, run `models.ValidateScope(&req.Scope)` **whenever `req.Scope.InScope` is non-empty — regardless of platform** — and return `400 ErrCodeInvalidField` with the validator's message on failure. Gating on `platform=="manual"` alone leaves a bypass: `{"platform":"hackerone","scope":{...garbage...}}` would skip validation since the platform string is valid. Validation is cheap and the data shape is identical across platforms.
- **Avoid a second default-application site:** the existing handler defaults `Type` to `bug-bounty`; manual mode wants `research`. Rather than re-implementing that rule here, factor the manual-project construction (defaults + `ValidateScope`) into a shared helper (see U2's decision) and have this handler delegate to it for manual projects, so CLI and web cannot drift. If full delegation to `App` is undesirable in the handler layer (it currently takes a `Store`, not `App`), put the shared helper in `pkg/models` or a small `internal/web/handlers` helper both paths import.
- No new route — this hardens the existing POST `/api/projects` path the dashboard already calls.
- Consider wrapping the request body in `http.MaxBytesReader` so an oversized inline scope is capped at the HTTP layer (mirrors U1's file-size cap).

**Patterns to follow:** existing field-validation + `writeError(... ErrCodeInvalidField ...)` flow in the same handler (`projects.go:107-142`); role gate already present (`RoleUser`).

**Test scenarios:**
- Happy path: POST manual project with valid inline scope → 201, scope persisted, counts correct, `Type=="research"`. Covers AE for R4.
- Integration/parity: a manual project created via this endpoint has the **same default `Type`** as one created via the CLI (U3) — asserts the shared-helper decision actually prevents drift.
- Error path: manual project with an invalid asset type in scope → 400 `ErrCodeInvalidField`, body names the bad value, nothing persisted.
- Error path: `platform=="hackerone"` (or any non-manual) **with** a non-empty invalid scope → 400, proving validation is not gated on the manual platform string.
- Error path: manual project with empty `in_scope` → 400.
- Edge case: platform project with no scope → unchanged behavior (still 201).
- Integration: created manual project is returned by the list endpoint with `platform=="manual"`.

**Verification:** `go test ./internal/web/...` green; invalid scope rejected at the API for any platform when a scope is supplied; CLI/web manual defaults match.

---

### U5. HackerOne hacker-tier clarification (T3-3)

**Goal:** Turn the hacker-tier 401 into a typed, actionable error that recommends manual mode, on the program/scope fetch paths a project-create actually hits.

**Requirements:** R5

**Dependencies:** U2 — **soft only.** The recommended command is a string literal, so U5 has no compile-time dependency on U2's code and can be built/tested independently. U2 should land first so the recommendation U5 prints is actually functional.

**Files:**
- Modify: `internal/platform/hackerone.go` (`GetProgram` / `FetchScope` 401 handling)
- Modify: `internal/core/app.go` (`CreateProject` external-error path at `:205-208` — surface the recommendation to the CLI user)
- Test: `internal/platform/hackerone_test.go`

**Approach:**
- On 401 from `GetProgram`/`FetchScope`, return a typed/wrapped error stating the token appears hacker-tier and that org-tier access is required for the program API, with a concrete next step: "create the project manually: `zerodaybuddy project create --manual --name <n> --scope-file <file>`".
- **Do NOT carry forward the existing `string(body)` interpolation.** All three current 401 sites (`fetchProgramsPage:123`, `GetProgram`, `FetchScope`) inline the raw response body into the error — copying that pattern would propagate a body-leak and violate R5. Build the message from the HTTP status code and a canned string only; if the body is wanted for diagnostics, log it at DEBUG, never in the returned error chain.
- In `CreateProject`, when wrapping the platform `ExternalError`, detect the hacker-tier signal and include the manual-mode recommendation in the user-facing message.
- Match the *wording/tone* of the existing `fetchProgramsPage` hint for consistency — but not its raw-body interpolation.

**Patterns to follow:** existing 401 hint in `hackerone.go` `fetchProgramsPage`; `pkgerrors.ExternalError` usage in `app.go:206`.

**Test scenarios:**
- Happy path: 200 from `GetProgram` → unchanged, returns program.
- Error path: 401 from `GetProgram` (httptest server) → error message mentions hacker-tier limitation and `--manual`. Covers AE for R5.
- Error path: 403 / other non-200 → existing generic handling preserved (no false "use manual mode" on unrelated failures).
- Edge case: raw response body is not dumped verbatim into the user-facing recommendation.

**Verification:** `go test ./internal/platform/...` green; simulated hacker-tier 401 yields an actionable message naming manual mode.

---

## System-Wide Impact

- **Interaction graph:** new `CreateManualProject` is called by the CLI (U3) and conceptually mirrored by the web handler (U4, which calls `store.CreateProject` directly after shared validation). `ValidateScope` (U1) is the shared chokepoint for both. T3-3 (U5) only changes error text/paths on the existing platform fetch.
- **Error propagation:** scope validation failures surface as `400 ErrCodeInvalidField` on web and as CLI errors before any store write; hacker-tier 401s become typed actionable errors rather than raw dumps.
- **State lifecycle risks:** ensure no partial project is persisted when scope validation fails (validate before `store.CreateProject` in every path).
- **API surface parity:** CLI and web must apply the *same* `ValidateScope` — the plan routes both through U1 specifically to prevent drift. Verify both reject the same invalid-type fixture.
- **Integration coverage:** a manual project must be fully usable downstream (recon/scan read `project.Scope.IsInScope`); U1's tests assert `IsInScope` behavior on loaded scope so manual projects aren't second-class.
- **Unchanged invariants:** existing `CreateProject` platform path, the `AssetType` enum *values*, `matchAsset`/`IsInScope` matching logic, and the DB (JSON) serialization of scope are explicitly not modified. The web POST route signature is unchanged (only added validation). **Exception:** `Scope`/`Asset` gain `yaml` struct tags (additive, tag-only) — this does not affect JSON serialization or matching, but it is a real edit to `models.go`, so the earlier "off models.go" framing means *off its logic*, not *zero edits*.

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| YAML scope files silently parse to empty (missing struct tags) | Add `yaml` tags to `Scope`/`Asset` (U1); a YAML-specific happy-path test guards the regression. |
| CLI and web scope validation **and defaults** drift apart | Single shared `ValidateScope` + shared manual-project construction helper (U2); cross-path parity test on both validation and default `Type`. |
| `--scope-file` reads sensitive host files (`validation.FilePath` is weak) | Add an extension allowlist after `FilePath`, plus a file-size cap and strict decode in `LoadScopeFile` (U1/U3). |
| Web scope validation bypassed via non-manual platform | Run `ValidateScope` whenever a scope is supplied, not gated on `platform=="manual"` (U4); explicit test. |
| Raw HackerOne 401 body leaks into user-facing errors | U5 builds messages from status code only; existing `string(body)` interpolation is dropped, not copied; test asserts no verbatim body. |
| `gopkg.in/yaml.v3` is only an indirect dep | `go mod tidy` promotes it to direct on first import; it is already in the module graph (no new download). |
| Making `--platform`/`--program` optional breaks the existing required-flag UX | Enforce per-branch requirements inside `RunE` with explicit errors + a comment at the branch point; regression test the platform branch. |
| T3-3 over-fires "use manual mode" on unrelated auth failures | Gate the recommendation strictly on 401 from program/scope fetch; test 403/other stay generic. |
| Manual project missing fields breaks downstream recon/scan | Shared helper defaults `Type`/`Status`/`Handle`; U1 tests assert `IsInScope` works on loaded scope. |

---

## Documentation / Operational Notes

- Update `CLAUDE.md` (Configuration / commands) and `README` to document `project create --manual --scope-file` and the scope-file schema, referencing `examples/scope.yaml`.
- Update the punch list (`docs/brainstorms/codebase-punch-list-requirements.md`) success-criteria checkboxes for T3-1/T3-2/T3-3 as units land.
- Consider seeding `docs/solutions/` with a note on the scope-file format and the "one validator, two entry points" decision (no such dir exists yet).

---

## Sources & References

- **Origin document:** [docs/brainstorms/codebase-punch-list-requirements.md](docs/brainstorms/codebase-punch-list-requirements.md) — §3 Tier 3 (T3-1/T3-2/T3-3), Open Question #3, §8 success criteria.
- Related code: `internal/core/app.go:191`, `pkg/models/models.go:13` / `:296`, `pkg/validation/validation.go:40`, `cmd/zerodaybuddy/main.go:118`, `internal/web/handlers/projects.go:90`, `internal/platform/hackerone.go`.
- Related prior plans: `docs/plans/2026-05-10-004-feat-data-model-rest-handlers-plan.md` (T2-2, established the web create handler this plan hardens).
- Archived context: `docs/archive/HACKERONE_HACKER_LIMITATIONS.md`, `docs/archive/ZERODAYBUDDY_TEST_REPORT.md`.
