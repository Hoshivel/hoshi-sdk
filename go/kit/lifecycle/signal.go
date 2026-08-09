package lifecycle

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// SignalContext is a context cancelled by an operating-system signal that
// remembers which signal it was.
//
// signal.NotifyContext cancels but discards the signal, and the difference
// matters when explaining a shutdown after the fact: SIGINT is a person at a
// terminal, SIGTERM is an orchestrator taking the instance away, and SIGHUP is
// usually neither on purpose. "The service stopped" answers nothing; "SIGTERM
// arrived 4 seconds after the readiness probe started failing" answers most of
// it.
type SignalContext struct {
	context.Context

	mu  sync.Mutex
	sig os.Signal
}

// NotifySignals returns a context cancelled when one of sigs arrives, and a
// stop function that releases the signal handler. With no signals given it
// watches the two that mean "stop": interrupt and SIGTERM.
func NotifySignals(parent context.Context, sigs ...os.Signal) (*SignalContext, func()) {
	if len(sigs) == 0 {
		sigs = []os.Signal{os.Interrupt, syscall.SIGTERM}
	}
	ctx, cancel := context.WithCancel(parent)
	sc := &SignalContext{Context: ctx}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)
	go func() {
		select {
		case s := <-ch:
			sc.mu.Lock()
			sc.sig = s
			sc.mu.Unlock()
			cancel()
		case <-ctx.Done():
		}
	}()
	return sc, func() {
		signal.Stop(ch)
		cancel()
	}
}

// Signal is the signal that cancelled the context, or nil if something else did.
func (s *SignalContext) Signal() os.Signal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sig
}

// SignalName names the signal for a log line, or "" when no signal arrived.
func (s *SignalContext) SignalName() string {
	if sig := s.Signal(); sig != nil {
		return sig.String()
	}
	return ""
}
