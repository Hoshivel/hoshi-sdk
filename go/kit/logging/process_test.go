package logging

import (
	"log/slog"
	"testing"
)

// resetProcess puts the package-level logger back so tests do not leak state
// into each other.
func resetProcess(t *testing.T) {
	t.Helper()
	processMu.Lock()
	process = nil
	processMu.Unlock()
	t.Cleanup(func() {
		processMu.Lock()
		process = nil
		processMu.Unlock()
	})
}

// TestProcessAccessorsWithoutSetup covers the case a service's diagnostics test
// is in: it exercises the diagnostics keys without installing a logger. The
// accessors must behave, and a value written must be the value read back.
func TestProcessAccessorsWithoutSetup(t *testing.T) {
	resetProcess(t)

	if Installed() == nil {
		t.Fatal("Installed returned nil")
	}

	SetLevel(slog.LevelWarn)
	if got := Level(); got != slog.LevelWarn {
		t.Errorf("Level = %v, want warn", got)
	}
	if Debugging() {
		t.Error("Debugging is true at warn")
	}

	SetDebug(true)
	if !Debugging() {
		t.Error("Debugging is false after SetDebug(true)")
	}

	// Leaving debug returns to the configured level, not to info. A deployment
	// running at warn must not silently become an info one because somebody
	// looked at a problem once.
	SetDebug(false)
	if got := Level(); got != slog.LevelWarn {
		t.Errorf("after leaving debug, Level = %v, want warn", got)
	}
}

// TestSetupInstallsForProcessAccessors pins the wiring: the accessors must act
// on the logger Setup installed, not on the fallback. Without this, the control
// plane would report and change a logger that nothing is writing to.
func TestSetupInstallsForProcessAccessors(t *testing.T) {
	resetProcess(t)

	o := Defaults()
	o.Level = LevelWarn
	o.Console = discardWriter{}
	l, err := Setup(o)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if Installed() != l {
		t.Fatal("Installed is not the logger Setup returned")
	}
	if got := Level(); got != slog.LevelWarn {
		t.Errorf("Level = %v, want warn", got)
	}

	// The two halves of the API address the same logger.
	SetDebug(true)
	if !l.Debugging() {
		t.Error("package SetDebug did not reach the installed logger")
	}
	l.SetDebug(false)
	if Debugging() {
		t.Error("method SetDebug did not reach the package accessors")
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
