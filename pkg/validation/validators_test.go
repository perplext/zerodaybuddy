package validation

import (
	"strings"
	"testing"
)

func TestUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
		errMsg   string
	}{
		{"valid simple", "john_doe", false, ""},
		{"valid with numbers", "user123", false, ""},
		{"valid with dots", "john.doe", false, ""},
		{"valid with hyphens", "john-doe", false, ""},
		{"empty", "", true, "cannot be empty"},
		{"too short", "ab", true, "at least 3 characters"},
		{"too long", strings.Repeat("a", 51), true, "too long"},
		{"special chars", "user@test", true, "only contain letters"},
		{"spaces", "john doe", true, "only contain letters"},
		{"reserved admin", "admin", true, "reserved"},
		{"reserved root", "root", true, "reserved"},
		{"reserved system", "system", true, "reserved"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Username(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("Username() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Username() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{"valid strong", "MyStr0ng!Pass", false, ""},
		{"valid complex", "P@ssw0rd123", false, ""},
		{"valid long", "ThisIsAVeryLongSecureString123!", false, ""},
		{"empty", "", true, "cannot be empty"},
		{"too short", "Pass1!", true, "at least 8 characters"},
		{"too long", strings.Repeat("a", 129), true, "too long"},
		{"no variety", "password", true, "at least 3 of"},
		{"only lowercase", "abcdefghij", true, "at least 3 of"},
		{"only uppercase", "ABCDEFGHIJ", true, "at least 3 of"},
		{"only numbers", "12345678", true, "at least 3 of"},
		{"weak password", "Password123!", true, "too common or weak"},
		{"contains weak", "mypassword123!", true, "too common or weak"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Password(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Password() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Password() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		platform string
		wantErr  bool
		errMsg   string
	}{
		{"valid hackerone", strings.Repeat("a", 40), "hackerone", false, ""},
		{"valid hackerone long", strings.Repeat("a", 64), "hackerone", false, ""},
		{"valid bugcrowd", strings.Repeat("x", 32), "bugcrowd", false, ""},
		{"valid generic", "some-api-key-here-1234567890", "other", false, ""},
		{"empty", "", "hackerone", true, "cannot be empty"},
		{"hackerone too short", "abc123", "hackerone", true, "at least 40"},
		{"bugcrowd too short", "abc", "bugcrowd", true, "too short"},
		{"generic too short", "abc", "other", true, "too short"},
		{"generic too long", strings.Repeat("a", 513), "other", true, "too long"},
		{"with bearer prefix", "Bearer " + strings.Repeat("a", 40), "hackerone", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := APIKey(tt.key, tt.platform)
			if (err != nil) != tt.wantErr {
				t.Errorf("APIKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("APIKey() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestPositiveInteger(t *testing.T) {
	tests := []struct {
		name      string
		value     int
		fieldName string
		wantErr   bool
	}{
		{"valid positive", 10, "count", false},
		{"valid one", 1, "count", false},
		{"zero", 0, "count", true},
		{"negative", -5, "count", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PositiveInteger(tt.value, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("PositiveInteger() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIntegerRange(t *testing.T) {
	tests := []struct {
		name      string
		value     int
		min       int
		max       int
		fieldName string
		wantErr   bool
	}{
		{"valid in range", 50, 1, 100, "percentage", false},
		{"valid at min", 1, 1, 100, "percentage", false},
		{"valid at max", 100, 1, 100, "percentage", false},
		{"below min", 0, 1, 100, "percentage", true},
		{"above max", 101, 1, 100, "percentage", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IntegerRange(tt.value, tt.min, tt.max, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("IntegerRange() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		wantErr  bool
	}{
		{"valid critical", "critical", false},
		{"valid high", "high", false},
		{"valid medium", "medium", false},
		{"valid low", "low", false},
		{"valid info", "info", false},
		{"valid uppercase", "HIGH", false},
		{"valid with spaces", " medium ", false},
		{"invalid", "severe", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Severity(tt.severity)
			if (err != nil) != tt.wantErr {
				t.Errorf("Severity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMigrationName(t *testing.T) {
	tests := []struct {
		name          string
		migrationName string
		wantErr       bool
		errMsg        string
	}{
		{"valid simple", "add_users_table", false, ""},
		{"valid with numbers", "add_column_v2", false, ""},
		{"empty", "", true, "cannot be empty"},
		{"too short", "ab", true, "at least 3 characters"},
		{"too long", strings.Repeat("a", 51), true, "too long"},
		{"uppercase", "ADD_USERS", true, "lowercase letters"},
		{"spaces", "add users", true, "lowercase letters"},
		{"special chars", "add-users", true, "lowercase letters"},
		{"valid complex", "add_users_table_with_index_v2", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MigrationName(tt.migrationName)
			if (err != nil) != tt.wantErr {
				t.Errorf("MigrationName() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("MigrationName() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal string", "hello world", "hello world"},
		{"with null bytes", "hello\x00world", "helloworld"},
		{"with tabs", "hello\tworld", "hello world"},
		{"with newlines", "hello\nworld", "hello world"},
		{"with carriage return", "hello\rworld", "hello world"},
		{"with spaces", "  hello  world  ", "hello  world"},
		{"with control chars", "hello\x01\x02world", "helloworld"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"needs truncation", "hello world", 5, "hello"},
		{"unicode safe", "hello 世界", 7, "hello 世"},
		{"empty", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("TruncateString() = %v, want %v", result, tt.expected)
			}
			if len([]rune(result)) > tt.maxLen {
				t.Errorf("TruncateString() result too long: %d > %d", len([]rune(result)), tt.maxLen)
			}
		})
	}
}