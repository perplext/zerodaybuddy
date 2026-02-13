package utils

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
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

// toSlogLevel converts a LogLevel to slog.Level
func (l LogLevel) toSlogLevel() slog.Level {
	switch l {
	case DEBUG:
		return slog.LevelDebug
	case INFO:
		return slog.LevelInfo
	case WARN:
		return slog.LevelWarn
	case ERROR:
		return slog.LevelError
	case FATAL:
		return slog.LevelError + 4 // Custom level above Error
	default:
		return slog.LevelInfo
	}
}

// LogFormat represents the log output format
type LogFormat string

const (
	TextFormat LogFormat = "text"
	JSONFormat LogFormat = "json"
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

// Logger wraps slog.Logger with printf-style convenience methods and
// sensitive field redaction. It preserves the existing API while delegating
// to Go's standard structured logging.
type Logger struct {
	slog    *slog.Logger
	level   *slog.LevelVar
	logFile io.WriteCloser
}

// sensitiveKeys is the set of field names whose values are redacted in log output.
var sensitiveKeys = map[string]bool{
	"password": true, "secret": true, "token": true,
	"api_key": true, "apikey": true, "authorization": true,
	"cookie": true, "credentials": true, "credential": true,
	"current_password": true, "new_password": true,
}

// RedactingHandler wraps an slog.Handler and masks values of sensitive keys.
type RedactingHandler struct {
	inner slog.Handler
}

func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	// Clone the record with redacted attributes
	redacted := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		redacted.AddAttrs(h.redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, redacted)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var redacted []slog.Attr
	for _, a := range attrs {
		redacted = append(redacted, h.redactAttr(a))
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(redacted)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func (h *RedactingHandler) redactAttr(a slog.Attr) slog.Attr {
	if sensitiveKeys[strings.ToLower(a.Key)] {
		return slog.String(a.Key, "[REDACTED]")
	}
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		var redacted []slog.Attr
		for _, ga := range attrs {
			redacted = append(redacted, h.redactAttr(ga))
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(redacted...)}
	}
	return a
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
	l := &Logger{
		level: new(slog.LevelVar),
	}
	l.level.Set(config.Level.toSlogLevel())

	// Build the writer: console only, or console + file
	var w io.Writer = os.Stdout
	if config.EnableFile && config.LogDir != "" {
		if err := os.MkdirAll(config.LogDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create log directory: %v\n", err)
			os.Exit(1)
		}
		logFile := &lumberjack.Logger{
			Filename:   filepath.Join(config.LogDir, "zerodaybuddy.log"),
			MaxSize:    config.MaxFileSize,
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge,
			Compress:   config.Compress,
		}
		l.logFile = logFile
		w = io.MultiWriter(os.Stdout, logFile)
	}

	// Build the slog handler (text or JSON), wrapped by RedactingHandler
	opts := &slog.HandlerOptions{
		Level:     l.level,
		AddSource: true,
	}
	var handler slog.Handler
	if config.Format == JSONFormat {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}
	handler = &RedactingHandler{inner: handler}

	l.slog = slog.New(handler)
	return l
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

// SetLevel changes the log level at runtime.
func (l *Logger) SetLevel(level LogLevel) {
	l.level.Set(level.toSlogLevel())
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() LogLevel {
	sl := l.level.Level()
	switch {
	case sl <= slog.LevelDebug:
		return DEBUG
	case sl <= slog.LevelInfo:
		return INFO
	case sl <= slog.LevelWarn:
		return WARN
	case sl <= slog.LevelError:
		return ERROR
	default:
		return FATAL
	}
}

// IsLevelEnabled checks if a log level is enabled
func (l *Logger) IsLevelEnabled(level LogLevel) bool {
	return l.slog.Enabled(context.Background(), level.toSlogLevel())
}

// Debug logs a debug message (printf-style)
func (l *Logger) Debug(format string, args ...interface{}) {
	l.slog.Debug(fmt.Sprintf(format, args...))
}

// Info logs an info message (printf-style)
func (l *Logger) Info(format string, args ...interface{}) {
	l.slog.Info(fmt.Sprintf(format, args...))
}

// Warn logs a warning message (printf-style)
func (l *Logger) Warn(format string, args ...interface{}) {
	l.slog.Warn(fmt.Sprintf(format, args...))
}

// Error logs an error message (printf-style)
func (l *Logger) Error(format string, args ...interface{}) {
	l.slog.Error(fmt.Sprintf(format, args...))
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.slog.Log(context.Background(), slog.LevelError+4, fmt.Sprintf(format, args...))
	l.Close()
	os.Exit(1)
}

// DebugWithFields logs a debug message with structured key-value pairs
func (l *Logger) DebugWithFields(message string, fields map[string]interface{}) {
	l.slog.Debug(message, mapToAttrs(fields)...)
}

// InfoWithFields logs an info message with structured key-value pairs
func (l *Logger) InfoWithFields(message string, fields map[string]interface{}) {
	l.slog.Info(message, mapToAttrs(fields)...)
}

// WarnWithFields logs a warning message with structured key-value pairs
func (l *Logger) WarnWithFields(message string, fields map[string]interface{}) {
	l.slog.Warn(message, mapToAttrs(fields)...)
}

// ErrorWithFields logs an error message with structured key-value pairs
func (l *Logger) ErrorWithFields(message string, fields map[string]interface{}) {
	l.slog.Error(message, mapToAttrs(fields)...)
}

// FatalWithFields logs a fatal message with structured fields and exits
func (l *Logger) FatalWithFields(message string, fields map[string]interface{}) {
	l.slog.Log(context.Background(), slog.LevelError+4, message, mapToAttrs(fields)...)
	l.Close()
	os.Exit(1)
}

// LogSecure logs an object with sensitive data masked (handled by RedactingHandler)
func (l *Logger) LogSecure(level LogLevel, message string, obj interface{}) {
	l.slog.Log(context.Background(), level.toSlogLevel(), message, "data", obj)
}

// GetWriter returns an io.Writer for the log file
func (l *Logger) GetWriter() io.Writer {
	return l.logFile
}

// Slog returns the underlying *slog.Logger for callers that want
// direct access to structured logging.
func (l *Logger) Slog() *slog.Logger {
	return l.slog
}

// Close closes the log file
func (l *Logger) Close() {
	if l.logFile != nil {
		l.logFile.Close()
	}
}

// mapToAttrs converts a map to slog key-value pairs
func mapToAttrs(fields map[string]interface{}) []any {
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, k, v)
	}
	return attrs
}
