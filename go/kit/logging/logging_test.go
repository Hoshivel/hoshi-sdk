package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// opts is Defaults with the console silenced, so a test's own logging does not
// land in the test runner's output.
func opts(o Options) Options {
	base := Defaults()
	if o.Level != "" {
		base.Level = o.Level
	}
	if o.Format != "" {
		base.Format = o.Format
	}
	base.File = o.File
	base.Debug = o.Debug
	base.Source = o.Source
	if o.MaxSizeMB != 0 {
		base.MaxSizeMB = o.MaxSizeMB
	}
	base.Console = io.Discard
	if o.Console != nil {
		base.Console = o.Console
	}
	return base
}

func TestParseLevelRoundTrip(t *testing.T) {
	for _, name := range Levels() {
		level, err := ParseLevel(name)
		if err != nil {
			t.Fatalf("ParseLevel(%q): %v", name, err)
		}
		if got := LevelName(level); got != name {
			t.Fatalf("LevelName(ParseLevel(%q)) = %q", name, got)
		}
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Fatal("an unknown level must be an error, not a silent default")
	}
	// An absent value means the default rather than an error, so an operator who
	// omits the key gets info instead of a boot failure.
	if level, err := ParseLevel(""); err != nil || level != slog.LevelInfo {
		t.Fatalf("ParseLevel(\"\") = %v, %v; want info, nil", level, err)
	}
}

func TestValidate(t *testing.T) {
	for name, o := range map[string]Options{
		"unknown level":     {Level: "verbose", Stderr: true},
		"unknown format":    {Format: "logfmt", Stderr: true},
		"nowhere to write":  {Stderr: false},
		"negative size":     {Stderr: true, MaxSizeMB: -1},
		"negative retain":   {Stderr: true, RetainDays: -1},
		"negative maxfiles": {Stderr: true, MaxFiles: -1},
	} {
		if err := o.Validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("the defaults do not validate: %v", err)
	}
}

// Debug mode has to be reversible: an operator who runs at warn and turns debug
// on at runtime must land back on warn, not on the info default.
func TestSetDebugReturnsToConfiguredLevel(t *testing.T) {
	log, err := New(opts(Options{Level: LevelWarn, File: filepath.Join(t.TempDir(), "x.log")}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()

	if log.Debugging() {
		t.Fatal("debug must be off at warn level")
	}
	log.SetDebug(true)
	if !log.Debugging() || log.Level() != slog.LevelDebug {
		t.Fatalf("SetDebug(true) left level at %v", log.Level())
	}
	log.SetDebug(false)
	if log.Level() != slog.LevelWarn {
		t.Fatalf("leaving debug mode landed on %v, want warn", log.Level())
	}
}

func TestDebugOptionImpliesDebugLevel(t *testing.T) {
	log, err := New(opts(Options{Level: LevelError, Debug: true}))
	if err != nil {
		t.Fatal(err)
	}
	if !log.Debugging() {
		t.Fatal("debug: true must win over a higher configured level")
	}
	// Leaving debug mode returns to what the file asked for.
	log.SetDebug(false)
	if log.Level() != slog.LevelError {
		t.Fatalf("level after leaving debug = %v, want error", log.Level())
	}
}

// Turning the volume up must not write credentials to disk.
func TestSecretsAreRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "svc.log")
	log, err := New(opts(Options{Level: LevelDebug, Format: FormatJSON, File: path}))
	if err != nil {
		t.Fatal(err)
	}
	log.Info("connect",
		"password", "hunter2",
		"control.secret", "s3cr3t-value",
		"refresh_token", "rt-abc",
		"sealing_key", "k-abc",
		"authorization", "Bearer abc",
		"key_id", "console",
		"user", "ayaka",
	)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	written := string(body)
	for _, secret := range []string{"hunter2", "s3cr3t-value", "rt-abc", "k-abc", "Bearer abc"} {
		if strings.Contains(written, secret) {
			t.Fatalf("secret %q reached the log: %s", secret, written)
		}
	}
	// A key id names a secret, it is not one — and it is what an operator needs
	// when signatures are being rejected.
	for _, keep := range []string{"console", "ayaka"} {
		if !strings.Contains(written, keep) {
			t.Fatalf("%q should not have been redacted: %s", keep, written)
		}
	}
}

func TestFileSinkAppendsAndKeepsConsole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deep", "svc.log")
	log, err := New(opts(Options{File: path}))
	if err != nil {
		t.Fatalf("a missing directory should be created: %v", err)
	}
	log.Info("first")
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening must append: a restart that truncated its own log would erase
	// the evidence of why it restarted.
	log2, err := New(opts(Options{File: path}))
	if err != nil {
		t.Fatal(err)
	}
	log2.Info("second")
	if err := log2.Close(); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "first") || !strings.Contains(string(body), "second") {
		t.Fatalf("log file lost a line across the restart: %s", body)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if perm := info.Mode().Perm(); perm != logFileMode {
		t.Fatalf("log file mode = %o, want %o (logs are not world-readable)", perm, logFileMode)
	}
}

func TestRollOnSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "svc.log")
	log, err := New(opts(Options{File: path, MaxSizeMB: 1}))
	if err != nil {
		t.Fatal(err)
	}
	// 1 MB of records, in chunks big enough not to take all day.
	filler := strings.Repeat("x", 4096)
	for i := 0; i < 400; i++ {
		log.Info("padding a log past its size cap", "i", i, "filler", filler)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected the log to have rolled, found %d file(s)", len(entries))
	}
	// The live name must still be the configured one: whatever collects logs is
	// pointed at that path and must not have to follow the rolls.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the live log file must keep its configured name: %v", err)
	}
}

func TestRollOnDayTurn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "svc.log")
	day := time.Date(2026, 8, 1, 23, 59, 0, 0, time.UTC)
	r, err := newRotator(Options{File: path}, func() time.Time { return day })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte("before midnight\n")); err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return day.Add(2 * time.Minute) } // next day
	if _, err := r.Write([]byte("after midnight\n")); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(live), "before midnight") {
		t.Fatalf("the day turn should have moved yesterday's line out of the live file: %s", live)
	}
	if !strings.Contains(string(live), "after midnight") {
		t.Fatalf("today's line is missing from the live file: %s", live)
	}
	if got := len(r.rolls()); got != 1 {
		t.Fatalf("expected exactly 1 rolled file, found %d", got)
	}
}

// Retention only means something if something ever rolls, which is why the
// rotator rolls daily as well as on size. This checks the deletion half.
func TestRetainDaysDeletesOldRolls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "svc.log")

	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	old := path + "." + now.AddDate(0, 0, -20).Format(rollStamp)
	recent := path + "." + now.AddDate(0, 0, -1).Format(rollStamp)
	unrelated := filepath.Join(dir, "other-service.log")
	for _, f := range []string{old, recent, unrelated} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The clock goes in at construction, not after: newRotator prunes once
	// during startup, so a clock installed on the returned value would arrive
	// after the deletion it is meant to control. Passing it here also means
	// this test covers the startup prune — the one that catches up after a
	// service was down longer than its retention window — rather than only the
	// explicit call below.
	r, err := newRotator(Options{File: path, RetainDays: 14}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err == nil {
		t.Fatal("the startup prune kept a roll past the retention window")
	}
	r.prune()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(old); err == nil {
		t.Fatal("a roll past the retention window was kept")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatal("a roll inside the retention window was deleted")
	}
	// Another service's log in the same directory is not this rotator's to
	// delete.
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("prune deleted a file it does not own")
	}
}

func TestMaxFilesCapsRolls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "svc.log")
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		name := path + "." + now.Add(-time.Duration(i)*time.Hour).Format(rollStamp)
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := newRotator(Options{File: path, MaxFiles: 2}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	r.prune()

	kept := r.rolls()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 {
		t.Fatalf("max_files=2 kept %d rolls", len(kept))
	}
	// The newest two survive.
	for _, f := range kept {
		if f.at.Before(now.Add(-3 * time.Hour)) {
			t.Fatalf("max_files kept an older roll (%s) over a newer one", f.at)
		}
	}
}

// Every record logged while handling a request has to carry that request's id,
// including records from packages that know nothing about HTTP.
func TestRequestIDTravelsOnTheContext(t *testing.T) {
	var out strings.Builder
	log, err := New(opts(Options{Console: &out}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestID(t.Context(), "abc123")
	log.InfoContext(ctx, "did something")
	log.Info("outside any request")

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %s", len(lines), out.String())
	}
	if !strings.Contains(lines[0], "request=abc123") {
		t.Fatalf("the request id did not reach the record: %s", lines[0])
	}
	if strings.Contains(lines[1], "request=") {
		t.Fatalf("a record outside a request grew a request id: %s", lines[1])
	}
	if RequestID(t.Context()) != "" {
		t.Fatal("a bare context must not report a request id")
	}
}

func TestBadLogPathFailsAtStartup(t *testing.T) {
	// A path whose parent is a file, not a directory: the operator can still see
	// this error, which is the whole point of failing here rather than later.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(opts(Options{File: filepath.Join(file, "svc.log")})); err == nil {
		t.Fatal("an unusable log path must fail at startup, not silently log nowhere")
	}
}
