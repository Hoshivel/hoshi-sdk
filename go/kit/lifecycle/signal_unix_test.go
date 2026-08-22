//go:build !windows

package lifecycle_test

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/hoshivel/hoshi-sdk/go/kit/lifecycle"
)

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
