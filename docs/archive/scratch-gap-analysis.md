# ZeroDayBuddy Gap Analysis -- Scratch Notes

## Analysis completed: 2026-02-12

### Key files reviewed:
- go.mod, go.sum
- CLAUDE.md, README.md, USAGE-GUIDE.md, .github/SECURITY.md
- .github/workflows/ci.yml, release.yml, claude.yml
- .gitignore
- internal/core/app.go, errors.go
- internal/platform/platform.go, hackerone.go, bugcrowd.go
- internal/recon/scanner.go, service.go, scanner_factory.go
- internal/recon/scanner_subfinder.go, scanner_amass.go, scanner_httpx.go
- internal/recon/scanner_naabu.go, scanner_katana.go, scanner_wayback.go
- internal/recon/scanner_ffuf.go, scanner_nuclei.go
- internal/scan/service.go
- internal/storage/store.go, migrations/migration.go
- internal/storage/migrations/sql/001-005
- internal/auth/service.go, password.go, tokens.go
- internal/web/server.go
- internal/report/service.go
- pkg/config/config.go
- pkg/models/models.go
- pkg/validation/validation.go
- pkg/errors/errors.go

### Test coverage snapshot (all tests pass):
- internal/recon: 27.8% (critical gap)
- cmd/zerodaybuddy: 41.7%
- internal/web/handlers: 55.0%
- internal/core: 57.5%
- internal/storage: 62.8%

### P0 Critical Findings:
1. matchAsset() and isSubdomain() are stubs -- scope checking broken
2. HTTPX scanner return type mismatch with recon service
3. Wayback scanner name mismatch ("wayback" vs "waybackurls")
4. Hardcoded JWT secret fallback

### Next steps if continuing:
- Implement matchAsset() wildcard matching and isSubdomain()
- Fix HTTPX type mismatch in recon service
- Fix wayback scanner name registration
- Add WAL mode to SQLite connection
- Update CI Go version matrix and action versions
- Add govulncheck/gosec to CI
- Create Makefile and .golangci.yml
- Fix config file permissions (0644 -> 0600)
- Update outdated dependencies
