# GitHub Issues Progress Tracker

## Branch: refactor/modernization-phase1
## Last Commit: f62f094

## Issues to Resolve

### Bugs
- [ ] #5 - Auth handlers never wired into web server (Critical)
- [ ] #6 - PDF report format accepted but not implemented (Medium)
- [ ] #7 - Scope bypass via strings.Contains (High/Security)
- [ ] #8 - GetProgram fetches ALL Immunefi bounties (Medium/Perf)
- [ ] #9 - No pagination for platform API calls (Low)

### Enhancements
- [ ] #10 - Wire middleware into web server routes
- [ ] #11 - Add graceful shutdown signal handling
- [ ] #12 - Add tests for config Save()
- [ ] #13 - Add tests for version command
- [ ] #14 - Partial failure handling for bulk ops

## Key Files
- `internal/web/server.go` — #5, #10
- `pkg/validation/validators.go` — #6
- `pkg/validation/project.go` — #7 (scope bypass)
- `internal/platform/immunefi.go` — #8
- `internal/platform/hackerone.go`, `bugcrowd.go` — #9
- `cmd/zerodaybuddy/main.go` — #11
- `pkg/config/config.go` — #12
- `cmd/zerodaybuddy/version.go`, `internal/version/` — #13
- `internal/storage/bulk.go` — #14
