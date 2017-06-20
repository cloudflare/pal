package log

import (
	"fmt"
	"log"
	"os"
)

type logLevel int

// Largely inspired by (and largely copied from) the CFSSL log package
// https://github.com/cloudflare/cfssl/tree/master/log

// The various logging levels.
const (
	LevelDebug = iota
	LevelInfo
	LevelWarning
	LevelError
	LevelCritical
	LevelFatal
)

func (l logLevel) String() string {
	switch l {
	case LevelDebug:
		return "[DEBUG] "
	case LevelInfo:
		return "[INFO] "
	case LevelWarning:
		return "[WARNING] "
	case LevelError:
		return "[ERROR] "
	case LevelCritical:
		return "[CRITICAL] "
	case LevelFatal:
		return "[FATAL] "
	default:
		panic("unknown log level")
	}
}

// Level stores the current logging level.
var Level logLevel = LevelDebug
var disabled = false

func outputf(l logLevel, format string, v []interface{}) {
	if l >= Level && !disabled {
		log.Printf(fmt.Sprint(l, format), v...)
	}
}

func output(l logLevel, v []interface{}) {
	if l >= Level && !disabled {
		log.Print(l, fmt.Sprint(v...))
	}
}

// Fatalf logs a formatted message at the "fatal" level and then exits. The
// arguments are handled in the same manner as fmt.Printf.
func Fatalf(format string, v ...interface{}) {
	outputf(LevelFatal, format, v)
	os.Exit(1)
}

// Fatal logs its arguments at the "fatal" level and then exits. The arguments
// are handled in the same manner as fmt.Print.
func Fatal(v ...interface{}) {
	output(LevelFatal, v)
	os.Exit(1)
}

// Criticalf logs a formatted message at the "critical" level. The arguments are
// handled in the same manner as fmt.Printf.
func Criticalf(format string, v ...interface{}) {
	outputf(LevelCritical, format, v)
}

// Critical logs its arguments at the "critical" level. The arguments are
// handled in the same manner as fmt.Print.
func Critical(v ...interface{}) {
	output(LevelCritical, v)
}

// Errorf logs a formatted message at the "error" level. The arguments are
// handled in the same manner as fmt.Printf.
func Errorf(format string, v ...interface{}) {
	outputf(LevelError, format, v)
}

// Error logs its arguments at the "error" level. The arguments are handled in
// the same manner as fmt.Print.
func Error(v ...interface{}) {
	output(LevelError, v)
}

// Warningf logs a formatted message at the "warning" level. The arguments are
// handled in the same manner as fmt.Printf.
func Warningf(format string, v ...interface{}) {
	outputf(LevelWarning, format, v)
}

// Warning logs its arguments at the "warning" level. The arguments are handled
// in the same manner as fmt.Print.
func Warning(v ...interface{}) {
	output(LevelWarning, v)
}

// Infof logs a formatted message at the "info" level. The arguments are handled
// in the same manner as fmt.Printf.
func Infof(format string, v ...interface{}) {
	outputf(LevelInfo, format, v)
}

// Info logs its arguments at the "info" level. The arguments are handled in the
// same manner as fmt.Print.
func Info(v ...interface{}) {
	output(LevelInfo, v)
}

// Debugf logs a formatted message at the "debug" level. The arguments are
// handled in the same manner as fmt.Printf.
func Debugf(format string, v ...interface{}) {
	outputf(LevelDebug, format, v)
}

// Debug logs its arguments at the "debug" level. The arguments are handled in
// the same manner as fmt.Print.
func Debug(v ...interface{}) {
	output(LevelDebug, v)
}

// Disable disables logging altogether, regardless of level. However, calls to
// Fatal and Fatalf will still halt the process; they just won't log anything.
// Calling Disable when logging is already disabled is a no-op.
func Disable() {
	disabled = true
}

// Enable enables logging if it has previously been disabled with Disable.
// Calling Enable when logging is already enabled is a no-op.
func Enable() {
	disabled = false
}
