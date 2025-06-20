package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	// DEBUG level for detailed troubleshooting information
	DEBUG LogLevel = iota
	// INFO level for general operational information
	INFO
	// WARN level for potentially harmful situations
	WARN
	// ERROR level for error events that might still allow the application to continue
	ERROR
	// FATAL level for severe error events that will lead the application to abort
	FATAL
)

// String returns the string representation of a log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogFormat represents the log output format
type LogFormat string

const (
	TextFormat LogFormat = "text"
	JSONFormat LogFormat = "json"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[37m"
	colorWhite  = "\033[97m"
)

// LoggerConfig holds configuration for the logger
type LoggerConfig struct {
	Level        LogLevel
	Format       LogFormat
	EnableColors bool
	EnableFile   bool
	LogDir       string
	MaxFileSize  int // MB
	MaxBackups   int
	MaxAge       int // days
	Compress     bool
}

// Logger is a configurable logger with support for different log levels and formats
type Logger struct {
	config     LoggerConfig
	logger     *log.Logger
	fileLogger *log.Logger
	logFile    io.WriteCloser
}

// NewLogger creates a new logger instance
func NewLogger(logDir string, debug bool) *Logger {
	config := LoggerConfig{
		Level:        INFO,
		Format:       TextFormat,
		EnableColors: true,
		EnableFile:   logDir != "",
		LogDir:       logDir,
		MaxFileSize:  100,
		MaxBackups:   5,
		MaxAge:       30,
		Compress:     true,
	}
	
	if debug {
		config.Level = DEBUG
	}
	
	return NewLoggerWithConfig(config)
}

// NewLoggerWithConfig creates a new logger instance with the given configuration
func NewLoggerWithConfig(config LoggerConfig) *Logger {
	logger := &Logger{
		config: config,
	}

	// Create console logger
	logger.logger = log.New(os.Stdout, "", 0)

	// Create file logger if enabled
	if config.EnableFile && config.LogDir != "" {
		if err := os.MkdirAll(config.LogDir, 0755); err != nil {
			log.Fatalf("Failed to create log directory: %v", err)
		}

		// Use lumberjack for log rotation
		logFile := &lumberjack.Logger{
			Filename:   filepath.Join(config.LogDir, "zerodaybuddy.log"),
			MaxSize:    config.MaxFileSize, // MB
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge, // days
			Compress:   config.Compress,
		}

		logger.fileLogger = log.New(logFile, "", 0)
		logger.logFile = logFile
	}

	return logger
}

// ParseLogLevel parses a string log level to LogLevel
func ParseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn", "warning":
		return WARN
	case "error":
		return ERROR
	case "fatal":
		return FATAL
	default:
		return INFO
	}
}

// SetLevel sets the logger's level
func (l *Logger) SetLevel(level LogLevel) {
	l.config.Level = level
}

// getColorForLevel returns the ANSI color code for a log level
func (l *Logger) getColorForLevel(level LogLevel) string {
	if !l.config.EnableColors {
		return ""
	}
	
	switch level {
	case DEBUG:
		return colorGray
	case INFO:
		return colorBlue
	case WARN:
		return colorYellow
	case ERROR:
		return colorRed
	case FATAL:
		return colorRed
	default:
		return colorWhite
	}
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string            `json:"timestamp"`
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	File      string            `json:"file,omitempty"`
	Line      int               `json:"line,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// log logs a message with the given level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.config.Level {
		return
	}

	// Get caller information
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "unknown"
		line = 0
	}
	// Extract just the file name from the path
	file = filepath.Base(file)

	// Format message
	message := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Format based on configuration
	var consoleMessage, fileMessage string
	
	if l.config.Format == JSONFormat {
		entry := LogEntry{
			Timestamp: timestamp,
			Level:     level.String(),
			Message:   message,
			File:      file,
			Line:      line,
		}
		
		jsonBytes, _ := json.Marshal(entry)
		consoleMessage = string(jsonBytes)
		fileMessage = string(jsonBytes)
	} else {
		// Text format
		color := l.getColorForLevel(level)
		reset := ""
		if color != "" {
			reset = colorReset
		}
		
		baseMessage := fmt.Sprintf("[%s] [%s] [%s:%d] %s", timestamp, level.String(), file, line, message)
		consoleMessage = fmt.Sprintf("%s%s%s", color, baseMessage, reset)
		fileMessage = baseMessage
	}

	// Log to console
	l.logger.Println(consoleMessage)

	// Log to file if enabled
	if l.config.EnableFile && l.fileLogger != nil {
		l.fileLogger.Println(fileMessage)
	}

	// Exit if FATAL
	if level == FATAL {
		l.Close()
		os.Exit(1)
	}
}

// logWithFields logs a message with additional structured fields
func (l *Logger) logWithFields(level LogLevel, message string, fields map[string]interface{}) {
	if level < l.config.Level {
		return
	}

	// Get caller information
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "unknown"
		line = 0
	}
	file = filepath.Base(file)

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	if l.config.Format == JSONFormat {
		entry := LogEntry{
			Timestamp: timestamp,
			Level:     level.String(),
			Message:   message,
			File:      file,
			Line:      line,
			Fields:    fields,
		}
		
		jsonBytes, _ := json.Marshal(entry)
		consoleMessage := string(jsonBytes)
		
		l.logger.Println(consoleMessage)
		if l.config.EnableFile && l.fileLogger != nil {
			l.fileLogger.Println(consoleMessage)
		}
	} else {
		// For text format, append fields as key=value pairs
		fieldsStr := ""
		if len(fields) > 0 {
			var pairs []string
			for k, v := range fields {
				pairs = append(pairs, fmt.Sprintf("%s=%v", k, v))
			}
			fieldsStr = " " + strings.Join(pairs, " ")
		}
		
		color := l.getColorForLevel(level)
		reset := ""
		if color != "" {
			reset = colorReset
		}
		
		baseMessage := fmt.Sprintf("[%s] [%s] [%s:%d] %s%s", timestamp, level.String(), file, line, message, fieldsStr)
		consoleMessage := fmt.Sprintf("%s%s%s", color, baseMessage, reset)
		
		l.logger.Println(consoleMessage)
		if l.config.EnableFile && l.fileLogger != nil {
			l.fileLogger.Println(baseMessage)
		}
	}

	if level == FATAL {
		l.Close()
		os.Exit(1)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
}

// Structured logging methods with fields
func (l *Logger) DebugWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(DEBUG, message, fields)
}

func (l *Logger) InfoWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(INFO, message, fields)
}

func (l *Logger) WarnWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(WARN, message, fields)
}

func (l *Logger) ErrorWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(ERROR, message, fields)
}

func (l *Logger) FatalWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(FATAL, message, fields)
}

// GetWriter returns an io.Writer for the log file
func (l *Logger) GetWriter() io.Writer {
	return l.logFile
}

// Close closes the log file
func (l *Logger) Close() {
	if l.logFile != nil {
		l.logFile.Close()
	}
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() LogLevel {
	return l.config.Level
}

// IsLevelEnabled checks if a log level is enabled
func (l *Logger) IsLevelEnabled(level LogLevel) bool {
	return level >= l.config.Level
}

// LogSecure logs an object with sensitive data masked
// This method will mask common sensitive field names
func (l *Logger) LogSecure(level LogLevel, message string, obj interface{}) {
	if level < l.config.Level {
		return
	}
	
	// Convert to JSON, then mask sensitive fields
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		l.Error("Failed to marshal object for secure logging: %v", err)
		return
	}
	
	// Parse as generic map to mask sensitive fields
	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		l.Error("Failed to unmarshal object for secure logging: %v", err)
		return
	}
	
	// Mask sensitive fields
	maskSensitiveFields(data)
	
	// Re-marshal masked data
	maskedBytes, err := json.Marshal(data)
	if err != nil {
		l.Error("Failed to marshal masked object: %v", err)
		return
	}
	
	// Log the masked version
	l.log(level, "%s: %s", message, string(maskedBytes))
}

// maskSensitiveFields recursively masks sensitive data in a map
func maskSensitiveFields(data map[string]interface{}) {
	sensitiveFields := []string{
		"password", "Password", "PASSWORD",
		"secret", "Secret", "SECRET",
		"token", "Token", "TOKEN",
		"key", "Key", "KEY",
		"credential", "Credential", "CREDENTIAL",
		"current_password", "new_password",
		"CurrentPassword", "NewPassword",
	}
	
	for key, value := range data {
		// Check if this field should be masked
		for _, sensitive := range sensitiveFields {
			if key == sensitive {
				data[key] = "[REDACTED]"
				break
			}
		}
		
		// Recursively handle nested objects
		if nested, ok := value.(map[string]interface{}); ok {
			maskSensitiveFields(nested)
		}
	}
}
