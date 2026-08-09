// Package lifecycle records what a process does at its edges: how long it has
// been running, which signal ended it, how the teardown went, and how long the
// individual operations along the way took.
//
// # Why this is not part of kit/logging
//
// All of it writes to a log, which is why it started out inside that package.
// But what it models is the life of a process, not a logging pipeline: a
// service that swapped its logger would keep every line of this, and a caller
// that only wants to configure log files has no use for any of it. Left where
// it was, kit/logging was the package every service imported for two unrelated
// reasons, and neither one could be read without the other in the way.
//
// The split shows up in the API: this package takes a Logger rather than owning
// one. Anything that can write four levels will do — including *slog.Logger and
// kit/logging.Logger, which embeds one.
//
// Zero dependencies, standard library only.
package lifecycle

import "time"

// Logger is the part of a logger this package writes through.
//
// It is deliberately the smallest useful surface: *slog.Logger satisfies it as
// it stands, so does kit/logging.Logger, and so does a caller's own type that
// wants to see these records go somewhere else entirely.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// processStart is as close to the real process start as this package can get.
// Package initialisation runs before main, so an uptime measured from here is
// honest even for a service that dies during startup.
var processStart = time.Now()

// Uptime is how long this process has been running.
func Uptime() time.Duration { return time.Since(processStart) }
