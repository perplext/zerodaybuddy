package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"debug", DEBUG},
		{"DEBUG", DEBUG},
		{"info", INFO},
		{"INFO", INFO},
		{"warn", WARN},
		{"warning", WARN},
		{"WARN", WARN},
		{"error", ERROR},
		{"ERROR", ERROR},
		{"fatal", FATAL},
		{"FATAL", FATAL},
		{"unknown", INFO}, // default
		{"", INFO},        // default
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := ParseLogLevel(test.input)
			if result != test.expected {
				t.Errorf("ParseLogLevel(%s) = %v, want %v", test.input, result, test.expected)
			}
		})
	}
}

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{DEBUG, "DEBUG"},
		{INFO, "INFO"},
		{WARN, "WARN"},
		{ERROR, "ERROR"},
		{FATAL, "FATAL"},
		{LogLevel(999), "UNKNOWN"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			result := test.level.String()
			if result != test.expected {
				t.Errorf("LogLevel(%d).String() = %s, want %s", test.level, result, test.expected)
			}
		})
	}
}

func TestNewLoggerWithConfig(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := LoggerConfig{
		Level:        DEBUG,
		Format:       TextFormat,
		EnableColors: true,
		EnableFile:   true,
		LogDir:       tempDir,
		MaxFileSize:  10,
		MaxBackups:   3,
		MaxAge:       7,
		Compress:     true,
	}

	logger := NewLoggerWithConfig(config)
	if logger == nil {
		t.Fatal("NewLoggerWithConfig returned nil")
	}

	if logger.config.Level != DEBUG {
		t.Errorf("Expected level DEBUG, got %v", logger.config.Level)
	}

	if logger.config.Format != TextFormat {
		t.Errorf("Expected format TextFormat, got %v", logger.config.Format)
	}

	logger.Close()
}

func TestLogger_SetLevel(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := LoggerConfig{
		Level:       INFO,
		Format:      TextFormat,
		EnableFile:  false,
		LogDir:      tempDir,
	}

	logger := NewLoggerWithConfig(config)
	defer logger.Close()

	if logger.GetLevel() != INFO {
		t.Errorf("Expected initial level INFO, got %v", logger.GetLevel())
	}

	logger.SetLevel(DEBUG)
	if logger.GetLevel() != DEBUG {
		t.Errorf("Expected level DEBUG after SetLevel, got %v", logger.GetLevel())
	}
}

func TestLogger_IsLevelEnabled(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := LoggerConfig{
		Level:       WARN,
		Format:      TextFormat,
		EnableFile:  false,
		LogDir:      tempDir,
	}

	logger := NewLoggerWithConfig(config)
	defer logger.Close()

	tests := []struct {
		level    LogLevel
		expected bool
	}{
		{DEBUG, false},
		{INFO, false},
		{WARN, true},
		{ERROR, true},
		{FATAL, true},
	}

	for _, test := range tests {
		t.Run(test.level.String(), func(t *testing.T) {
			result := logger.IsLevelEnabled(test.level)
			if result != test.expected {
				t.Errorf("IsLevelEnabled(%v) = %v, want %v", test.level, result, test.expected)
			}
		})
	}
}

func TestLogger_JSONFormat(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	config := LoggerConfig{
		Level:        DEBUG,
		Format:       JSONFormat,
		EnableColors: false,
		EnableFile:   false,
		LogDir:       tempDir,
	}

	logger := NewLoggerWithConfig(config)

	// Log a message
	logger.Info("Test message")

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Parse JSON
	var entry LogEntry
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		t.Fatal("No output captured")
	}

	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if entry.Level != "INFO" {
		t.Errorf("Expected level INFO, got %s", entry.Level)
	}

	if entry.Message != "Test message" {
		t.Errorf("Expected message 'Test message', got %s", entry.Message)
	}

	if entry.File == "" {
		t.Error("Expected file to be set")
	}

	if entry.Line == 0 {
		t.Error("Expected line to be set")
	}

	logger.Close()
}

func TestLogger_WithFields(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	config := LoggerConfig{
		Level:        DEBUG,
		Format:       JSONFormat,
		EnableColors: false,
		EnableFile:   false,
		LogDir:       tempDir,
	}

	logger := NewLoggerWithConfig(config)

	fields := map[string]interface{}{
		"user_id": 123,
		"action":  "login",
		"ip":      "192.168.1.1",
	}

	// Log a message with fields
	logger.InfoWithFields("User logged in", fields)

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Parse JSON
	var entry LogEntry
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		t.Fatal("No output captured")
	}

	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if entry.Level != "INFO" {
		t.Errorf("Expected level INFO, got %s", entry.Level)
	}

	if entry.Message != "User logged in" {
		t.Errorf("Expected message 'User logged in', got %s", entry.Message)
	}

	if entry.Fields == nil {
		t.Fatal("Expected fields to be set")
	}

	if userID, ok := entry.Fields["user_id"].(float64); !ok || userID != 123 {
		t.Errorf("Expected user_id to be 123, got %v", entry.Fields["user_id"])
	}

	if action, ok := entry.Fields["action"].(string); !ok || action != "login" {
		t.Errorf("Expected action to be 'login', got %v", entry.Fields["action"])
	}

	logger.Close()
}

func TestLogger_FileLogging(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := LoggerConfig{
		Level:        DEBUG,
		Format:       TextFormat,
		EnableColors: false,
		EnableFile:   true,
		LogDir:       tempDir,
		MaxFileSize:  10,
		MaxBackups:   3,
		MaxAge:       7,
		Compress:     false,
	}

	logger := NewLoggerWithConfig(config)

	// Log some messages
	logger.Info("Test message 1")
	logger.Warn("Test message 2")
	logger.Error("Test message 3")

	logger.Close()

	// Check if log file was created
	logFile := filepath.Join(tempDir, "zerodaybuddy.log")
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Fatalf("Log file was not created: %s", logFile)
	}

	// Read log file content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)
	if !strings.Contains(logContent, "Test message 1") {
		t.Error("Log file does not contain 'Test message 1'")
	}

	if !strings.Contains(logContent, "Test message 2") {
		t.Error("Log file does not contain 'Test message 2'")
	}

	if !strings.Contains(logContent, "Test message 3") {
		t.Error("Log file does not contain 'Test message 3'")
	}

	if !strings.Contains(logContent, "[INFO]") {
		t.Error("Log file does not contain '[INFO]'")
	}

	if !strings.Contains(logContent, "[WARN]") {
		t.Error("Log file does not contain '[WARN]'")
	}

	if !strings.Contains(logContent, "[ERROR]") {
		t.Error("Log file does not contain '[ERROR]'")
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	config := LoggerConfig{
		Level:        WARN, // Only WARN, ERROR, FATAL should be logged
		Format:       TextFormat,
		EnableColors: false,
		EnableFile:   false,
		LogDir:       tempDir,
	}

	logger := NewLoggerWithConfig(config)

	// Log messages at different levels
	logger.Debug("Debug message")   // Should not appear
	logger.Info("Info message")     // Should not appear
	logger.Warn("Warning message")  // Should appear
	logger.Error("Error message")   // Should appear

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if strings.Contains(output, "Debug message") {
		t.Error("Debug message should not appear in output")
	}

	if strings.Contains(output, "Info message") {
		t.Error("Info message should not appear in output")
	}

	if !strings.Contains(output, "Warning message") {
		t.Error("Warning message should appear in output")
	}

	if !strings.Contains(output, "Error message") {
		t.Error("Error message should appear in output")
	}

	logger.Close()
}

func TestNewLogger_BackwardCompatibility(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test with debug=false
	logger1 := NewLogger(tempDir, false)
	if logger1.GetLevel() != INFO {
		t.Errorf("Expected level INFO for debug=false, got %v", logger1.GetLevel())
	}
	logger1.Close()

	// Test with debug=true
	logger2 := NewLogger(tempDir, true)
	if logger2.GetLevel() != DEBUG {
		t.Errorf("Expected level DEBUG for debug=true, got %v", logger2.GetLevel())
	}
	logger2.Close()
}