package lifecycle_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hoshivel/hoshi-sdk/go/kit/lifecycle"
	"github.com/hoshivel/hoshi-sdk/go/kit/logging"
)

// The two loggers a service actually has must satisfy the interface without
// being adapted. This is the whole basis of the split — if it ever stops
// holding, the package has grown a requirement that belongs to one logger.
var (
	_ lifecycle.Logger = (*logging.Logger)(nil)
	_ lifecycle.Logger = (*slog.Logger)(nil)
)

// fileLogger writes to path and nowhere else, so a test can read back exactly
// what a service would have left behind.
func fileLogger(t *testing.T, path string) *logging.Logger {
	t.Helper()
	o := logging.Defaults()
	o.Level = logging.LevelDebug
	o.File = path
	o.Console = io.Discard
	log, err := logging.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return log
}

func TestShutdownRecordsCauseAndFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "svc.log")
	log := fileLogger(t, path)

	down := lifecycle.BeginShutdown(log, "signal", "signal", "terminated", "active_sessions", 3)
	down.Step("control listener", nil)
	down.Step("drain", os.ErrDeadlineExceeded, "remaining", 2)
	down.Done()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(written)
	for _, want := range []string{
		"shutting down", "reason=signal", "terminated", "active_sessions=3",
		"shutdown step failed", "step=drain", "remaining=2",
		"stopped with errors during shutdown", "failed_steps=1", "uptime=",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("shutdown record is missing %q:\n%s", want, body)
		}
	}
}

func TestOperationFailReturnsTheError(t *testing.T) {
	op := lifecycle.Begin(logging.Discard(), "open database", "path", "/tmp/x.db")
	if got := op.Fail(os.ErrPermission); got != os.ErrPermission {
		t.Fatalf("Fail returned %v, want the error it was given", got)
	}
}

func TestNotifySignalsReportsTheSignal(t *testing.T) {
	// SIGUSR1 rather than SIGTERM: the test signals its own process, and a stray
	// SIGTERM would take the test binary down with it.
	ctx, stop := lifecycle.NotifySignals(t.Context(), syscall.SIGUSR1)
	defer stop()

	if name := ctx.SignalName(); name != "" {
		t.Fatalf("no signal has arrived yet, got %q", name)
	}
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the context was not cancelled by the signal")
	}
	if name := ctx.SignalName(); name == "" {
		t.Fatal("the signal that stopped the service must be recoverable for the log")
	}
}

func TestUptimeRunsFromBeforeMain(t *testing.T) {
	// Package initialisation happens before any test does, so uptime is already
	// positive here. A service that dies during startup gets an honest number
	// for the same reason.
	if lifecycle.Uptime() <= 0 {
		t.Fatal("uptime must be measured from process start, not from first use")
	}
}
