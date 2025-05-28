package validation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		wantErr  bool
	}{
		{"valid hackerone", "hackerone", false},
		{"valid bugcrowd", "bugcrowd", false},
		{"valid with spaces", " hackerone ", false},
		{"valid uppercase", "BUGCROWD", false},
		{"invalid platform", "hackthebox", true},
		{"empty platform", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Platform(tt.platform)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConcurrency(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"valid minimum", 1, false},
		{"valid maximum", 100, false},
		{"valid middle", 50, false},
		{"invalid zero", 0, true},
		{"invalid negative", -1, true},
		{"invalid too high", 101, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Concurrency(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"valid http", 8080, false},
		{"valid https", 8443, false},
		{"valid max", 65535, false},
		{"invalid zero", 0, true},
		{"invalid negative", -1, true},
		{"invalid too high", 65536, true},
	}

	// Add privileged port test if not running as root
	if os.Geteuid() != 0 {
		tests = append(tests, struct {
			name    string
			port    int
			wantErr bool
		}{"privileged port", 80, true})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Port(tt.port)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"valid localhost", "localhost", false},
		{"valid IP", "192.168.1.1", false},
		{"valid IPv6", "::1", false},
		{"valid hostname", "example.com", false},
		{"valid subdomain", "api.example.com", false},
		{"invalid special chars", "example@com", true},
		{"invalid spaces", "example com", true},
		{"empty host", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Host(tt.host)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUUID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid UUID", "550e8400-e29b-41d4-a716-446655440000", false},
		{"valid UUID lowercase", "550e8400-e29b-41d4-a716-446655440000", false},
		{"invalid format", "not-a-uuid", true},
		{"invalid too short", "550e8400", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UUID(tt.id)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReportFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		wantErr bool
	}{
		{"valid markdown", "markdown", false},
		{"valid pdf", "pdf", false},
		{"valid uppercase", "MARKDOWN", false},
		{"valid with spaces", " pdf ", false},
		{"invalid format", "html", true},
		{"empty format", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ReportFormat(tt.format)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilePath(t *testing.T) {
	// Get current directory for testing
	cwd, _ := os.Getwd()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty path", "", false},
		{"relative path", "output.md", false},
		{"relative with dir", "reports/output.md", false},
		{"absolute in cwd", filepath.Join(cwd, "output.md"), false},
		{"path traversal dots", "../../../etc/passwd", true},
		{"path traversal encoded", "..%2F..%2Fetc%2Fpasswd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := FilePath(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://example.com", false},
		{"valid http", "http://example.com", false},
		{"valid with path", "https://example.com/api/v1", false},
		{"valid with port", "https://example.com:8443", false},
		{"invalid scheme", "ftp://example.com", true},
		{"invalid localhost", "http://localhost", true},
		{"invalid 127.0.0.1", "http://127.0.0.1", true},
		{"invalid private IP", "http://192.168.1.1", true},
		{"invalid no scheme", "example.com", true},
		{"empty url", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := URL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProjectName(t *testing.T) {
	tests := []struct {
		name        string
		projectName string
		wantErr     bool
	}{
		{"valid simple", "myproject", false},
		{"valid with hyphen", "my-project", false},
		{"valid with underscore", "my_project", false},
		{"valid alphanumeric", "project123", false},
		{"invalid spaces", "my project", true},
		{"invalid special chars", "my@project", true},
		{"invalid empty", "", true},
		{"invalid too long", string(make([]byte, 101)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProjectName(tt.projectName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandle(t *testing.T) {
	tests := []struct {
		name    string
		handle  string
		wantErr bool
	}{
		{"valid simple", "bugcrowd", false},
		{"valid with hyphen", "bug-crowd", false},
		{"valid with underscore", "bug_crowd", false},
		{"valid alphanumeric", "bugcrowd123", false},
		{"invalid spaces", "bug crowd", true},
		{"invalid special chars", "bug@crowd", true},
		{"invalid empty", "", true},
		{"invalid too long", string(make([]byte, 101)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Handle(tt.handle)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestScopeURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowInternal bool
		wantErr       bool
	}{
		{"valid external", "https://example.com", false, false},
		{"internal blocked", "http://localhost", false, true},
		{"internal allowed", "http://localhost", true, false},
		{"private IP blocked", "http://192.168.1.1", false, true},
		{"private IP allowed", "http://192.168.1.1", true, false},
		{"invalid URL", "not-a-url", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ScopeURL(tt.url, tt.allowInternal)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}