//go:build windows

package lifecycle_test

import "testing"

// TestNotifySignalsIsNotCoveredHere states what Windows cannot answer.
//
// The delivery test lives in signal_unix_test.go because it needs a signal the
// process can send to itself and survive. SIGUSR1 is the natural choice and it
// does not exist on Windows; SIGTERM does exist as a value, but os.Process
// .Signal on Windows supports only Kill, so nothing can actually be delivered.
//
// NotifySignals itself compiles and runs here — signal.Notify accepts
// os.Interrupt on Windows, and the Ctrl+C path does reach it. What is not
// covered is the assertion that the signal's *name* survives into the shutdown
// record, because that needs a delivered signal.
//
// Stated rather than silently absent: a test package that simply excludes a
// platform reads, from that platform, exactly like one that passes.
func TestNotifySignalsIsNotCoveredHere(t *testing.T) {
	t.Logf("SKIPPED, NOT PASSED: signal delivery is not testable on Windows " +
		"(no SIGUSR1, and os.Process.Signal supports only Kill). The guarantee " +
		"is held by signal_unix_test.go on the platforms that can deliver one.")
}
