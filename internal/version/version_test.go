package version

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetVersion(t *testing.T) {
	v := GetVersion()
	assert.NotEmpty(t, v)
	assert.Equal(t, Version, v)
}

func TestBuildInfo(t *testing.T) {
	info := BuildInfo()

	// Verify all expected fields are present
	assert.Contains(t, info, "ZeroDayBuddy")
	assert.Contains(t, info, Version)
	assert.Contains(t, info, "Git Commit:")
	assert.Contains(t, info, GitCommit)
	assert.Contains(t, info, "Build Date:")
	assert.Contains(t, info, BuildDate)
	assert.Contains(t, info, "Go Version:")
	assert.Contains(t, info, runtime.Version())
	assert.Contains(t, info, "Platform:")
	assert.Contains(t, info, runtime.GOOS+"/"+runtime.GOARCH)
}

func TestBuildInfoFormat(t *testing.T) {
	info := BuildInfo()
	lines := strings.Split(info, "\n")

	// Should have 5 lines: header, git commit, build date, go version, platform
	assert.Len(t, lines, 5, "BuildInfo should have 5 lines")
	assert.True(t, strings.HasPrefix(lines[0], "ZeroDayBuddy "))
	assert.True(t, strings.HasPrefix(lines[1], "Git Commit: "))
	assert.True(t, strings.HasPrefix(lines[2], "Build Date: "))
	assert.True(t, strings.HasPrefix(lines[3], "Go Version: "))
	assert.True(t, strings.HasPrefix(lines[4], "Platform: "))
}

func TestDefaultValues(t *testing.T) {
	// When not built with ldflags, defaults should be set
	assert.Equal(t, "0.1.0", Version)
	assert.Equal(t, "unknown", GitCommit)
	assert.Equal(t, "unknown", BuildDate)
	assert.Equal(t, runtime.Version(), GoVersion)
}
