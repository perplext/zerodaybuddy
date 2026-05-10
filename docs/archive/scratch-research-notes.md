# Framework Documentation Research Notes

## Project Context
- Go 1.24.0
- Currently uses: mattn/go-sqlite3 v1.14.17, sqlx v1.3.5, lumberjack.v2 v2.2.1
- Module: github.com/perplext/zerodaybuddy

## Research Topics
1. log/slog - custom handler, sensitive field masking, LevelVar, lumberjack, context logging, performance
2. modernc.org/sqlite - driver registration, PRAGMA, sqlx compatibility, cross-compilation
3. GoReleaser - full config, SBOM, multi-platform, homebrew, signing

## Key Findings Summary

### slog
- Custom Handler implements slog.Handler interface (Enabled, Handle, WithAttrs, WithGroup)
- LogValuer interface for type-level redaction
- ReplaceAttr in HandlerOptions for attribute-level filtering
- LevelVar for runtime level changes
- lumberjack.v2 works as io.Writer for both TextHandler and JSONHandler
- Context methods: slog.InfoContext(), slog.DebugContext() etc.

### modernc.org/sqlite
- Driver name: "sqlite" (not "sqlite3")
- Connection string uses _pragma for PRAGMA: "file:db.sqlite?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)"
- Supported: darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64, windows/arm64, etc.
- No CGO required - pure Go cross-compilation
- Compatible with sqlx (standard database/sql interface)

### GoReleaser
- v2 current, brews section deprecated in favor of homebrew_casks (v2.10+)
- sboms section with cyclonedx-gomod cmd
- signs section with cosign
- builds section with goos/goarch matrix
