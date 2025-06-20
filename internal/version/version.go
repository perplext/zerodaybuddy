package version

import (
	"fmt"
	"runtime"
)

// Version information - these will be set at build time
var (
	Version   = "0.1.0"          // Set via -ldflags at build time
	GitCommit = "unknown"        // Set via -ldflags at build time
	BuildDate = "unknown"        // Set via -ldflags at build time
	GoVersion = runtime.Version()
)

// BuildInfo returns formatted build information
func BuildInfo() string {
	return fmt.Sprintf(`ZeroDayBuddy %s
Git Commit: %s
Build Date: %s
Go Version: %s
Platform: %s/%s`, Version, GitCommit, BuildDate, GoVersion, runtime.GOOS, runtime.GOARCH)
}

// GetVersion returns just the version string
func GetVersion() string {
	return Version
}