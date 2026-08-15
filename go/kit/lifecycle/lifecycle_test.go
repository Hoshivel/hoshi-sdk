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

// readLog returns everything the service wrote, so a test can assert on what a
// given level actually let through.
func readLog(t *testing.T, path string) string {
	t.Helper()
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(written)
}

// levelLogger writes to path at the given level, so a test can assert what a
// deployment running at that level would actually have on disk. The whole
// point of BeginFailure is a difference that only exists above info.
func levelLogger(t *testing.T, path, level string) *logging.Logger {
	t.Helper()
	o := logging.Defaults()
	o.Level = level
	o.File = path
	o.Console = io.Discard
	log, err := logging.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return log
}

// A deployment at warn is the one that most needs to know its listener died,
// and it is exactly the one an info announcement is invisible to. Before
// BeginFailure existed, every service passed the triggering error as a field on
// BeginShutdown's info line, so a process that could not bind its port
// disappeared having written nothing at all.
func TestFailureIsAudibleAtWarn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "svc.log")
	log := levelLogger(t, path, logging.LevelWarn)

	down := lifecycle.BeginFailure(log, "listener failed", os.ErrPermission,
		"listener", "public", "addr", "127.0.0.1:26700")
	down.Step("database", nil)
	down.Done()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	out := readLog(t, path)
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "shutting down") {
		t.Errorf("the cause was not written at error:\n%s", out)
	}
	for _, want := range []string{
		`reason="listener failed"`, "permission denied", "listener=public", "addr=127.0.0.1:26700",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the cause line is missing %s:\n%s", want, out)
		}
	}
	// Tearing down neatly after a listener died is not stopping cleanly, and at
	// warn that summary would otherwise be the only line to survive.
	if strings.Contains(out, "stopped cleanly") {
		t.Errorf("a forced shutdown reported itself as clean:\n%s", out)
	}
	if !strings.Contains(out, "stopped after a failure") {
		t.Errorf("no summary survived at warn:\n%s", out)
	}
	// The successful step stays debug: this is the half the spec used to get
	// wrong in the other direction.
	if strings.Contains(out, "step=database") {
		t.Errorf("a successful step was written above debug:\n%s", out)
	}
}

// The counterpart of the above, and the half the ruling deliberately left
// alone: an orderly stop is normal operation, so warn drops it entirely.
func TestOrderlyShutdownStaysSilentAtWarn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "svc.log")
	log := levelLogger(t, path, logging.LevelWarn)

	down := lifecycle.BeginShutdown(log, "signal", "signal", "terminated")
	down.Step("control listener", nil)
	down.Done()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	if out := readLog(t, path); strings.TrimSpace(out) != "" {
		t.Errorf("an orderly shutdown must not be audible at warn, got:\n%s", out)
	}
}

// A failed step still outranks everything: it is how state gets left behind.
func TestFailedStepIsErrorEvenAfterAnOrderlyStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "svc.log")
	log := levelLogger(t, path, logging.LevelWarn)

	down := lifecycle.BeginShutdown(log, "signal", "signal", "terminated")
	down.Step("release leases", os.ErrDeadlineExceeded, "remaining", 2)
	down.Done()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	out := readLog(t, path)
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "step=\"release leases\"") {
		t.Errorf("a failed step must be error even at warn:\n%s", out)
	}
	if !strings.Contains(out, "failed_steps=1") {
		t.Errorf("the summary lost the failure count:\n%s", out)
	}
}

// nil means nothing forced this, so it is an orderly shutdown and is announced
// as one — callers with a single code path must not accidentally shout.
func TestBeginFailureWithoutAnErrorIsOrderly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "svc.log")
	log := levelLogger(t, path, logging.LevelWarn)

	lifecycle.BeginFailure(log, "signal", nil, "signal", "terminated").Done()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if out := readLog(t, path); strings.TrimSpace(out) != "" {
		t.Errorf("a nil cause must behave like BeginShutdown, got:\n%s", out)
	}
}
