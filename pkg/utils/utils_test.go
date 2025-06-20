package utils

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrentTime(t *testing.T) {
	before := time.Now()
	result := CurrentTime()
	after := time.Now()
	
	assert.True(t, !result.Before(before))
	assert.True(t, !result.After(after))
}

func TestTimePtr(t *testing.T) {
	now := time.Now()
	ptr := TimePtr(now)
	
	require.NotNil(t, ptr)
	assert.Equal(t, now, *ptr)
}

func TestMarshalJSON(t *testing.T) {
	type testData struct {
		Name string
		Age  int
	}

	data := testData{Name: "Test", Age: 25}
	result, err := MarshalJSON(data)
	
	require.NoError(t, err)
	assert.Contains(t, string(result), `"Name":"Test"`)
	assert.Contains(t, string(result), `"Age":25`)

	// Test with unmarshalable type
	_, err = MarshalJSON(make(chan int))
	assert.Error(t, err)
}

func TestUnmarshalJSON(t *testing.T) {
	type testData struct {
		Name string
		Age  int
	}

	jsonStr := `{"Name":"Test","Age":30}`
	var result testData
	
	err := UnmarshalJSON(jsonStr, &result)
	require.NoError(t, err)
	assert.Equal(t, "Test", result.Name)
	assert.Equal(t, 30, result.Age)

	// Test with invalid JSON
	err = UnmarshalJSON(`invalid`, &result)
	assert.Error(t, err)
}

func TestWriteAndReadFile(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test WriteFile
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("Hello, World!")
	
	err = WriteFile(testFile, testData)
	require.NoError(t, err)

	// Verify file exists
	info, err := os.Stat(testFile)
	require.NoError(t, err)
	assert.Equal(t, int64(len(testData)), info.Size())

	// Test ReadFile
	readData, err := ReadFile(testFile)
	require.NoError(t, err)
	assert.Equal(t, testData, readData)

	// Test WriteFile with subdirectory that doesn't exist
	nestedFile := filepath.Join(tmpDir, "subdir", "nested.txt")
	err = WriteFile(nestedFile, testData)
	require.NoError(t, err)

	// Test ReadFile with non-existent file
	_, err = ReadFile(filepath.Join(tmpDir, "nonexistent.txt"))
	assert.Error(t, err)
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{"valid http", "http://example.com", true},
		{"valid https", "https://example.com", true},
		{"valid with path", "https://example.com/path/to/resource", true},
		{"valid with query", "https://example.com?param=value", true},
		{"valid with port", "https://example.com:8080", true},
		{"invalid scheme", "ftp://example.com", false},
		{"no scheme", "example.com", false},
		{"empty string", "", false},
		{"invalid url", "not a url", false},
		{"malformed", "http://", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidURL(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeFileName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"alphanumeric", "test123", "test123"},
		{"with spaces", "test file", "test_file"},
		{"with dots", "test.file.txt", "test.file.txt"},
		{"with dashes", "test-file", "test-file"},
		{"with underscores", "test_file", "test_file"},
		{"with special chars", "test@#$%file", "test____file"},
		{"multiple spaces", "test   file", "test___file"},
		{"leading trailing spaces", "  test  ", "__test__"},
		{"empty string", "", ""},
		{"only special chars", "@#$%", "____"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeFileName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateSlug(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "Hello World", "hello-world"},
		{"with numbers", "Test 123", "test-123"},
		{"special chars", "Test@#$%&*()_+", "test"},
		{"multiple spaces", "Test   Multiple   Spaces", "test-multiple-spaces"},
		{"mixed case", "TestMixedCase", "testmixedcase"},
		{"already slug", "already-a-slug", "already-a-slug"},
		{"unicode", "Café São Paulo", "caf-so-paulo"},
		{"trailing spaces", "  Test  ", "test"},
		{"empty after clean", "@#$%", ""},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateSlug(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsInScope(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		inScope    []string
		outOfScope []string
		expected   bool
	}{
		{
			name:       "exact match in scope",
			url:        "https://example.com",
			inScope:    []string{"example.com"},
			outOfScope: []string{},
			expected:   true,
		},
		{
			name:       "subdomain in scope",
			url:        "https://api.example.com",
			inScope:    []string{"*.example.com"},
			outOfScope: []string{},
			expected:   true,
		},
		{
			name:       "exact match out of scope",
			url:        "https://example.com",
			inScope:    []string{"*.example.com"},
			outOfScope: []string{"example.com"},
			expected:   false,
		},
		{
			name:       "not in scope",
			url:        "https://other.com",
			inScope:    []string{"example.com"},
			outOfScope: []string{},
			expected:   false,
		},
		{
			name:       "multiple in scope",
			url:        "https://test.example.com",
			inScope:    []string{"*.example.com", "*.test.com"},
			outOfScope: []string{},
			expected:   true,
		},
		{
			name:       "subdomain out of scope",
			url:        "https://admin.example.com",
			inScope:    []string{"*.example.com"},
			outOfScope: []string{"admin.example.com"},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsInScope(tt.url, tt.inScope, tt.outOfScope)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		domain   string
		expected bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"wildcard match", "*.example.com", "api.example.com", true},
		{"wildcard no match base", "*.example.com", "example.com", false},
		{"no match", "example.com", "other.com", false},
		{"subdomain no match", "api.example.com", "app.example.com", false},
		{"deeper subdomain", "*.example.com", "v1.api.example.com", true},
		{"case insensitive", "Example.COM", "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchDomain(tt.pattern, tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSubdomain(t *testing.T) {
	tests := []struct {
		name      string
		subdomain string
		domain    string
		expected  bool
	}{
		{"is subdomain", "api.example.com", "example.com", true},
		{"deep subdomain", "v1.api.example.com", "example.com", true},
		{"not subdomain", "example.com", "example.com", false},
		{"different domain", "api.other.com", "example.com", false},
		{"partial match", "example.com.evil.com", "example.com", true},
		{"case insensitive", "API.EXAMPLE.COM", "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSubdomain(tt.subdomain, tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"less than second", 500 * time.Millisecond, "500ms"},
		{"exactly 1 second", 1 * time.Second, "1s"},
		{"seconds", 45 * time.Second, "45s"},
		{"minute", 1 * time.Minute, "1m 0s"},
		{"minutes and seconds", 2*time.Minute + 30*time.Second, "2m 30s"},
		{"hour", 1 * time.Hour, "1h 0m 0s"},
		{"complex", 2*time.Hour + 15*time.Minute + 30*time.Second, "2h 15m 30s"},
		{"zero", 0, "0ms"},
		{"negative", -5 * time.Second, "-5s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatDuration(tt.duration)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStringInSlice(t *testing.T) {
	slice := []string{"apple", "banana", "cherry"}

	tests := []struct {
		name     string
		str      string
		expected bool
	}{
		{"exists first", "apple", true},
		{"exists middle", "banana", true},
		{"exists last", "cherry", true},
		{"not exists", "orange", false},
		{"empty string in non-empty slice", "", false},
		{"case sensitive", "Apple", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringInSlice(tt.str, slice)
			assert.Equal(t, tt.expected, result)
		})
	}

	// Test with empty slice
	assert.False(t, StringInSlice("test", []string{}))
	
	// Test with slice containing empty string
	assert.True(t, StringInSlice("", []string{"", "test"}))
}

func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all duplicates",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "single element",
			input:    []string{"a"},
			expected: []string{"a"},
		},
		{
			name:     "preserve order",
			input:    []string{"c", "a", "b", "a", "c"},
			expected: []string{"c", "a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UniqueStrings(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"https url", "https://example.com/path", "example.com"},
		{"http url", "http://example.com", "example.com"},
		{"with port", "https://example.com:8080/path", "example.com"},
		{"subdomain", "https://api.example.com", "api.example.com"},
		{"no scheme", "example.com/path", ""},
		{"invalid url", "not a url", ""},
		{"empty string", "", ""},
		{"ip address", "http://192.168.1.1", "192.168.1.1"},
		{"with auth", "https://user:pass@example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractDomain(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFileExists(t *testing.T) {
	// Create temp file
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Test existing file
	assert.True(t, FileExists(tmpFile.Name()))

	// Test non-existing file
	assert.False(t, FileExists("/non/existent/file.txt"))

	// Test with directory (should return false)
	tmpDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	assert.False(t, FileExists(tmpDir))
}

func TestDirExists(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test existing directory
	assert.True(t, DirExists(tmpDir))

	// Test non-existing directory
	assert.False(t, DirExists("/non/existent/directory"))

	// Test with file (should return false)
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	assert.False(t, DirExists(tmpFile.Name()))
}