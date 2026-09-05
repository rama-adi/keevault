package client

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// Level controls how much the client writes to stderr.
type Level int

// Log levels, lowest first.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// ParseLevel maps a VAULT_LOG_LEVEL value to a Level. An empty value means
// info.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level %q, use debug, info, warn or error", s)
	}
}

// Logger writes plain status lines. It never receives secret material: the
// call sites pass counts and identifiers only.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
}

// NewLogger returns a Logger writing to out at the given level.
func NewLogger(out io.Writer, level Level) *Logger {
	return &Logger{out: out, level: level}
}

func (l *Logger) write(level Level, format string, args ...any) {
	if l == nil || level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, format+"\n", args...)
}

// Debugf writes a debug line.
func (l *Logger) Debugf(format string, args ...any) { l.write(LevelDebug, format, args...) }

// Infof writes an info line.
func (l *Logger) Infof(format string, args ...any) { l.write(LevelInfo, format, args...) }

// Warnf writes a warning line.
func (l *Logger) Warnf(format string, args ...any) { l.write(LevelWarn, format, args...) }

// Errorf writes an error line.
func (l *Logger) Errorf(format string, args ...any) { l.write(LevelError, format, args...) }
