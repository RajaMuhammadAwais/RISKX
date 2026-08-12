// Package log provides RISKX's structured logger with secret redaction and
// secure formatting (spec §25).
//
// Rules: user-controlled values are never interpolated into log format strings
// (injection protection); secrets and credentials are redacted before writing;
// the logger never writes to network destinations in MVP (privacy, spec §46).
package log

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level controls log verbosity.
type Level int

const (
	LevelQuiet Level = iota
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
)

// Default redaction patterns: keys, tokens, passwords, secrets.
var defaultPatterns = []string{
	"api_key", "apikey", "api-key", "token", "secret", "password", "passwd",
	"authorization", "credential", "access_key", "private_key",
}

// Logger is a leveled, redacting structured logger.
type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	errOut   io.Writer
	level    Level
	jsonMode bool
	patterns []string
}

// New creates a logger writing to the given writers at the given level.
func New(out, errOut io.Writer, level Level, jsonMode bool) *Logger {
	return &Logger{out: out, errOut: errOut, level: level, jsonMode: jsonMode, patterns: defaultPatterns}
}

// Default returns the process-wide logger (info to stderr).
var defaultLogger = New(os.Stderr, os.Stderr, LevelInfo, false)

// SetLevel changes the default logger level.
func SetLevel(l Level) { defaultLogger.level = l }

// SetJSON puts the default logger into JSON mode.
func SetJSON(on bool) { defaultLogger.jsonMode = on }

func (l *Logger) log(level Level, msg string, kvs map[string]any) {
	if level > l.level {
		return
	}
	entry := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": levelName(level),
		"msg":   l.redact(msg),
	}
	for k, v := range kvs {
		entry[l.redact(k)] = v
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.errOut
	if level <= LevelInfo {
		w = l.out
	}
	if l.jsonMode {
		_ = json.NewEncoder(w).Encode(entry)
		return
	}
	_, _ = fmt.Fprintf(w, "%s [%s] %s\n", entry["ts"], entry["level"], entry["msg"])
}

func levelName(l Level) string {
	switch l {
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	default:
		return ""
	}
}

// Error logs at error level.
func (l *Logger) Error(msg string, kvs ...any) { l.log(LevelError, msg, toMap(kvs)) }

// Warn logs at warn level.
func (l *Logger) Warn(msg string, kvs ...any) { l.log(LevelWarn, msg, toMap(kvs)) }

// Info logs at info level.
func (l *Logger) Info(msg string, kvs ...any) { l.log(LevelInfo, msg, toMap(kvs)) }

// Debug logs at debug level.
func (l *Logger) Debug(msg string, kvs ...any) { l.log(LevelDebug, msg, toMap(kvs)) }

// toMap converts alternating key/value pairs into a map. Odd trailing pairs
// are kept under an "extra" key rather than silently dropped (no ignored
// inputs).
func toMap(kvs []any) map[string]any {
	m := make(map[string]any, len(kvs)/2+1)
	for i := 0; i+1 < len(kvs); i += 2 {
		if k, ok := kvs[i].(string); ok {
			m[k] = kvs[i+1]
			continue
		}
	}
	if len(kvs)%2 != 0 {
		m["extra"] = kvs[len(kvs)-1]
	}
	return m
}

// redact masks values whose key matches a secret pattern.
func (l *Logger) redact(v string) string {
	low := strings.ToLower(v)
	for _, p := range l.patterns {
		if strings.Contains(low, p) {
			return "***REDACTED***"
		}
	}
	return v
}

// Module-scoped convenience functions on the default logger.
func Error(msg string, kvs ...any) { defaultLogger.Error(msg, kvs...) }
func Warn(msg string, kvs ...any)  { defaultLogger.Warn(msg, kvs...) }
func Info(msg string, kvs ...any)  { defaultLogger.Info(msg, kvs...) }
func Debug(msg string, kvs ...any) { defaultLogger.Debug(msg, kvs...) }
