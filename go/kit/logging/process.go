package logging

import (
	"log/slog"
	"sync"
)

// The process-wide logger.
//
// §11.4 of the platform conventions requires every managed service to expose
// diagnostics.log_level and diagnostics.debug through its own management
// descriptor, so an operator can turn the volume up on a service that is
// already smoking without restarting it. The code serving those keys lives in
// each service's adminplane — far from wherever main kept the *Logger, and
// reached over HTTP rather than called with it. Threading the logger down to
// there through every constructor in between is a lot of plumbing for one
// runtime switch, so this is the other half of the API: the same four
// operations, addressed to whichever logger this process installed.
//
// It is also how kit/lifecycle reaches a logger from a teardown path that never
// received one: lifecycle.BeginShutdown(logging.Installed(), …).
//
// Before Setup runs, these operate on a discard logger rather than panicking or
// silently doing nothing. A test that exercises only the diagnostics path can
// then call SetDebug and read Debugging back without installing anything, and
// the value it reads is the value it set.

var (
	processMu sync.Mutex
	process   *Logger
)

// current returns the installed logger, or a discard logger if Setup has not
// run. The fallback is created once and kept, so that a level set on it is
// still there to be read back.
func current() *Logger {
	processMu.Lock()
	defer processMu.Unlock()
	if process == nil {
		process = Discard()
	}
	return process
}

// setProcess records the logger Setup installed.
func setProcess(l *Logger) {
	processMu.Lock()
	defer processMu.Unlock()
	process = l
}

// Installed is the logger this process installed with Setup, or a discard
// logger if it has not run. It is never nil.
func Installed() *Logger { return current() }

// SetLevel changes the level of the installed logger. It also becomes the level
// that leaving debug mode returns to — see Logger.SetLevel.
func SetLevel(level slog.Level) { current().SetLevel(level) }

// SetDebug turns the most detailed logging on or off while the service runs.
// Turning it off returns to the configured level, not to info: a deployment
// running at warn must not quietly become an info one because somebody looked
// at a problem once.
func SetDebug(on bool) { current().SetDebug(on) }

// Level is the level currently in effect.
func Level() slog.Level { return current().Level() }

// Debugging reports whether debug records are currently being written. Call it
// before assembling anything expensive that only debug output would use.
func Debugging() bool { return current().Debugging() }
