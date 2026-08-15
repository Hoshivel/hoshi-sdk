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
	// caused records that this shutdown was triggered by a failure rather than
	// by a signal, so Done does not call the result clean.
	caused bool

	mu     sync.Mutex
	steps  int
	failed int
}

// BeginShutdown announces an orderly shutdown and starts recording it. reason
// is the cause in a few words — "signal", "operator requested" — and attrs
// carry the context that makes it actionable.
//
// The announcement is info, and a deployment running at warn will not see it.
// That is deliberate: an orderly stop is part of normal operation, and paying
// for it at warn would mean every routine restart shouts. A shutdown that was
// *caused by something going wrong* is not this function's job — use
// BeginFailure, which is audible at warn.
func BeginShutdown(log Logger, reason string, attrs ...any) *Shutdown {
	s := &Shutdown{log: log, begun: time.Now(), reason: reason}
	log.Info("shutting down", append([]any{
		"reason", reason,
		"uptime", Uptime().Round(time.Millisecond).String(),
	}, attrs...)...)
	return s
}

// BeginFailure announces a shutdown that something forced — a listener that
// could not bind, a dependency that will not answer — and records it the same
// way BeginShutdown does from there on.
//
// The difference is the level, and it is the whole point of having two
// functions. The triggering error goes out at error, not as a field on an info
// line, because the deployments that most need this record are the ones running
// at warn: there, an info announcement is dropped and the process disappears
// having written nothing at all. Done() will not report "stopped cleanly"
// afterwards either — the process died of something, and a summary saying
// otherwise is worse than no summary.
//
// A nil err means nothing forced this, so it is an orderly shutdown and is
// announced as one.
func BeginFailure(log Logger, reason string, err error, attrs ...any) *Shutdown {
	if err == nil {
		return BeginShutdown(log, reason, attrs...)
	}
	s := &Shutdown{log: log, begun: time.Now(), reason: reason, caused: true}
	log.Error("shutting down", append([]any{
		"reason", reason,
		"error", err,
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
//
// A shutdown opened by BeginFailure is also warn even when every step
// succeeded: tearing down neatly after a listener died is not stopping
// cleanly, and at warn that summary would otherwise be the only line the
// deployment could have seen.
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
	if s.caused {
		s.log.Warn("stopped after a failure", fields...)
		return
	}
	s.log.Info("stopped cleanly", fields...)
}
