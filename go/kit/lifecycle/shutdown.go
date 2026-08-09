package lifecycle

import (
	"sync"
	"time"
)

// Shutdown records why a service is stopping and what happened on the way down.
//
// A shutdown that goes wrong is the hardest thing to investigate afterwards:
// the process is gone, and by convention it says the least exactly when it is
// doing the most — closing listeners, draining work in flight, flushing state.
// This turns the teardown into a record with a cause at the top, one line per
// step, and a summary saying how long it took and what did not finish.
type Shutdown struct {
	log    Logger
	begun  time.Time
	reason string

	mu     sync.Mutex
	steps  int
	failed int
}

// BeginShutdown announces the shutdown and starts recording it. reason is the
// cause in a few words — "signal", "listener failed", "operator requested"
// — and attrs carry the context that makes it actionable.
func BeginShutdown(log Logger, reason string, attrs ...any) *Shutdown {
	s := &Shutdown{log: log, begun: time.Now(), reason: reason}
	log.Info("shutting down", append([]any{
		"reason", reason,
		"uptime", Uptime().Round(time.Millisecond).String(),
	}, attrs...)...)
	return s
}

// Step records the outcome of one teardown step. A failure is logged with its
// error and whatever context the caller passes; a success is debug-level detail
// nobody needs unless they are already looking.
func (s *Shutdown) Step(name string, err error, attrs ...any) {
	s.mu.Lock()
	s.steps++
	if err != nil {
		s.failed++
	}
	s.mu.Unlock()

	base := []any{
		"step", name,
		"elapsed", time.Since(s.begun).Round(time.Millisecond).String(),
	}
	if err != nil {
		s.log.Error("shutdown step failed", append(append(base, "error", err), attrs...)...)
		return
	}
	s.log.Debug("shutdown step done", append(base, attrs...)...)
}

// Done closes the record. It reports at warn level when a step failed, because
// a shutdown with a failed step is how state gets left behind — a lease not
// released, a connection not closed, a game not handed over — and that is the
// thing someone will be looking for later.
func (s *Shutdown) Done(attrs ...any) {
	s.mu.Lock()
	steps, failed := s.steps, s.failed
	s.mu.Unlock()

	fields := append([]any{
		"reason", s.reason,
		"took", time.Since(s.begun).Round(time.Millisecond).String(),
		"uptime", Uptime().Round(time.Millisecond).String(),
		"steps", steps,
	}, attrs...)
	if failed > 0 {
		s.log.Warn("stopped with errors during shutdown", append(fields, "failed_steps", failed)...)
		return
	}
	s.log.Info("stopped cleanly", fields...)
}
