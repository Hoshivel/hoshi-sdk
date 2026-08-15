// Package logging is this service's one channel for anything that is not a
// response: what it did, what it refused, and what went wrong.
//
// It is meant to be the same package in every service a team runs — same
// settings, same defaults, one implementation imported rather than a copy per
// repository. An operator who has configured one has configured all of them,
// and that becomes a property of the build rather than a convention somebody
// has to keep re-establishing.
//
// There is exactly one logger, installed process-wide as the slog default, so a
// package deep in the call graph can say something without being handed one —
// and so that turning the detail up is one setting rather than a rebuild. The
// standard library's log package is routed through it too, which keeps a stray
// log.Printf (or the http server's own error output) in the same file and the
// same format as everything else.
//
// Three things shape the rest:
//
//   - The console is never given up. A log file is an addition to standard
//     error, never a replacement, unless log.stderr is explicitly turned off.
//   - A log file that cannot be written must not take the service down. Disk
//     errors are reported once on standard error and then tolerated; the
//     alternative is a service that stops working because its logging did.
//   - Turning the volume up must not become a way to write credentials to
//     disk. Debug output is exactly where a token or a password would leak, so
//     attributes whose names say they carry a secret are replaced before they
//     reach any sink (see redact).
//
// The level lives in a slog.LevelVar, so it can be changed while the service
// runs — by the embedding process, without a restart. Source positions
// (AddSource) are decided at construction: they cost a stack walk per record,
// and paying that on every record for a switch that is rarely flipped is the
// wrong trade. A runtime switch to debug therefore gains the debug messages but
// not file:line; a restart with debug: true gains both.
package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Levels, in the words the configuration file uses.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Output formats. Text is for a person reading a terminal or a file; JSON is
// for something that collects and indexes it.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// Options is how the log behaves. It comes from the configuration file, and
// every field has a working default so that a deployment that says nothing
// still gets readable output on stderr.
type Options struct {
	// Level is the least severe message that is written. Debug is everything.
	Level string
	// Format is text or json.
	Format string
	// File is where to write, in addition to (or instead of) stderr. Empty
	// means stderr only, which is what a container or a systemd unit wants:
	// those already collect it, and a second copy inside the container goes
	// away with the container.
	File string
	// Stderr keeps the terminal copy when a file is configured. It defaults to
	// on: turning on a file should not silently take away the output somebody
	// was already watching.
	Stderr bool
	// MaxSizeMB is when the file is rolled aside. Zero means never on size —
	// the file still rolls at the day boundary.
	MaxSizeMB int
	// RetainDays and MaxFiles bound how much rolled-aside history is kept. Zero
	// means no bound of that kind; with both zero, nothing is ever deleted.
	RetainDays int
	MaxFiles   int

	// Debug is the mode a service is put into while something is being looked
	// at: every level, source positions, and the per-request and per-operation
	// tracing that is otherwise silent. It is separate from Level, which is the
	// deployment's standing choice and the one leaving debug mode returns to.
	Debug bool
	// Source adds file:line to every record. Debug implies it.
	Source bool

	// Console overrides where the non-file half of the output goes. Nil means
	// standard error, which is what a deployment always wants; tests set it so
	// their own logging does not land in the test runner's output.
	Console io.Writer
}

// Defaults is what a configuration that says nothing about logging gets.
func Defaults() Options {
	return Options{
		Level: LevelInfo, Format: FormatText, Stderr: true,
		MaxSizeMB: 32, RetainDays: 14, MaxFiles: 14,
	}
}

// ParseLevel resolves a configured level name.
func ParseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", LevelInfo:
		return slog.LevelInfo, nil
	case LevelDebug:
		return slog.LevelDebug, nil
	case LevelWarn, "warning":
		return slog.LevelWarn, nil
	case LevelError:
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (use debug, info, warn or error)", name)
}

// LevelName is the inverse of ParseLevel.
func LevelName(level slog.Level) string {
	switch {
	case level <= slog.LevelDebug:
		return LevelDebug
	case level <= slog.LevelInfo:
		return LevelInfo
	case level <= slog.LevelWarn:
		return LevelWarn
	default:
		return LevelError
	}
}

// Levels are the accepted level names, least severe first, for building
// configuration UIs.
func Levels() []string { return []string{LevelDebug, LevelInfo, LevelWarn, LevelError} }

// Validate reports what is wrong with these options, if anything.
func (o Options) Validate() error {
	if _, err := ParseLevel(o.Level); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(o.Format)) {
	case "", FormatText, FormatJSON:
	default:
		return fmt.Errorf("unknown log format %q (use text or json)", o.Format)
	}
	if o.File == "" && !o.Stderr {
		// Not a hypothetical: it is what "log.stderr: false" plus no file means,
		// and the service would run with no output at all.
		return fmt.Errorf("log.stderr is off and no log.file is set, so nothing would be written anywhere")
	}
	if o.MaxSizeMB < 0 || o.RetainDays < 0 || o.MaxFiles < 0 {
		return fmt.Errorf("log.max_size_mb, log.retain_days and log.max_files cannot be negative")
	}
	return nil
}

// Logger is the process logger together with the file it writes to, if any.
// It embeds *slog.Logger, so it is used exactly like one, and it satisfies
// io.Closer.
type Logger struct {
	*slog.Logger

	level *slog.LevelVar
	// configured is the level the configuration asked for, kept so that leaving
	// debug mode returns to it rather than to a hardcoded default.
	configured slog.Level
	file       *rotator
	opts       Options
	source     bool

	mu    sync.Mutex
	debug bool
}

// Setup builds the logger and installs it process-wide: as the slog default,
// and as the destination of the standard library's log package. It is called
// once, from main, before anything else can want to log.
func Setup(o Options) (*Logger, error) {
	l, err := New(o)
	if err != nil {
		return nil, err
	}
	slog.SetDefault(l.Logger)
	// slog.SetDefault already points the log package's default logger here; the
	// flags are cleared so its output does not carry a second timestamp of its
	// own in front of the structured one.
	log.SetFlags(0)
	// Record it for the package-level accessors in process.go, which is how the
	// diagnostics keys reach this logger at runtime.
	setProcess(l)
	return l, nil
}

// New builds a logger without installing it. It fails when the options are
// invalid or the log file cannot be opened — a path that cannot be written is
// a configuration mistake worth stopping for at startup, where the operator can
// still see the error, rather than discovering it in the silence where the logs
// should have been.
func New(o Options) (*Logger, error) {
	if o.Level == "" {
		o.Level = LevelInfo
	}
	if o.Format == "" {
		o.Format = FormatText
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	configured, _ := ParseLevel(o.Level)
	level := configured
	if o.Debug {
		level = slog.LevelDebug
	}

	l := &Logger{
		level:      new(slog.LevelVar),
		configured: configured,
		opts:       o,
		source:     o.Source || o.Debug,
		debug:      o.Debug,
	}
	l.level.Set(level)

	console := o.Console
	if console == nil {
		console = os.Stderr
	}
	var out io.Writer
	if o.Stderr || o.File == "" {
		out = console
	}
	if o.File != "" {
		file, err := newRotator(o, nil)
		if err != nil {
			return nil, err
		}
		l.file = file
		if out == nil {
			out = file
		} else {
			out = &teeSink{console: out, file: file}
		}
	}

	handlerOpts := &slog.HandlerOptions{
		Level:       l.level,
		AddSource:   l.source,
		ReplaceAttr: redact,
	}
	var handler slog.Handler
	if strings.EqualFold(o.Format, FormatJSON) {
		handler = slog.NewJSONHandler(out, handlerOpts)
	} else {
		handler = slog.NewTextHandler(out, handlerOpts)
	}
	l.Logger = slog.New(ContextHandler(handler))
	return l, nil
}

// Discard is a logger that writes nothing, for tests.
func Discard() *Logger {
	silent := slog.LevelError + 1
	l := &Logger{level: new(slog.LevelVar), configured: silent, opts: Defaults()}
	l.level.Set(silent)
	l.Logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: l.level}))
	return l
}

// SetDebug turns debug mode on or off while the service runs. Turning it off
// returns to the configured level rather than to a fixed one, so an operator
// who runs at warn does not silently end up at info after a debugging session.
func (l *Logger) SetDebug(on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debug = on
	if on {
		l.level.Set(slog.LevelDebug)
		return
	}
	l.level.Set(l.configured)
}

// SetLevel changes the level and updates what "leaving debug mode" returns to.
func (l *Logger) SetLevel(level slog.Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.configured = level
	l.debug = level <= slog.LevelDebug
	l.level.Set(level)
}

// Debugging reports whether debug output is currently being written. Call it
// before assembling anything expensive that only debug mode would use.
func (l *Logger) Debugging() bool { return l.level.Level() <= slog.LevelDebug }

// Level is the level currently in effect.
func (l *Logger) Level() slog.Level { return l.level.Level() }

// Path is the log file in use, or "" when writing to the console only.
func (l *Logger) Path() string { return l.opts.File }

// RetainDays is how long rolled-aside files are kept, for reporting.
func (l *Logger) RetainDays() int { return l.opts.RetainDays }

// Format is the output format in effect, for reporting.
func (l *Logger) Format() string { return l.opts.Format }

// Describe summarises the sinks in one line, for the startup log. An operator
// who cannot find the logs is usually looking in the wrong place, and this is
// the line that says which place is right.
func (l *Logger) Describe() string {
	where := "stderr"
	switch {
	case l.opts.File != "" && l.opts.Stderr:
		where = "stderr ＋ " + l.opts.File
	case l.opts.File != "":
		where = l.opts.File
	}
	return fmt.Sprintf("level=%s format=%s source=%t sink=%s",
		LevelName(l.Level()), l.opts.Format, l.source, where)
}

// Close flushes and closes the log file. The console is left alone.
func (l *Logger) Close() error {
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

// --- request identity -------------------------------------------------------

type requestIDKey struct{}

// WithRequestID marks a context as belonging to one request, so that everything
// logged while handling it can be found together afterwards.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the id carried by ctx, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewRequestID mints an identifier. It is short because its whole job is to be
// grep-able, and random because a counter would leak how much traffic this
// service handles to anyone who is given one.
func NewRequestID() string {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(raw[:])
}

// ContextHandler wraps a handler so that every record logged while handling a
// request carries that request's id — including records from packages that know
// nothing about HTTP. New applies it; it is exported so that a caller
// assembling its own handler (a test, most often) gets the same behaviour
// rather than a subtly different logger.
func ContextHandler(h slog.Handler) slog.Handler { return &contextHandler{Handler: h} }

type contextHandler struct{ slog.Handler }

func (h *contextHandler) Handle(ctx context.Context, record slog.Record) error {
	if id := RequestID(ctx); id != "" {
		record.AddAttrs(slog.String("request", id))
	}
	return h.Handler.Handle(ctx, record)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithGroup(name)}
}

// --- redaction ----------------------------------------------------------------

// redactedValue is what a secret-bearing attribute is replaced with. It is a
// fixed string rather than an elision of the real value: showing a prefix or a
// length of a secret is still showing part of it.
const redactedValue = "[redacted]"

// secretAttrs are attribute names that carry a credential outright. Matching is
// on the name alone, because the alternative — deciding per call site — is a
// rule that holds until the first person who forgets it.
var secretAttrs = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true,
	"authorization": true, "cookie": true, "set-cookie": true,
	"credential": true, "credentials": true, "signature": true,
	"api_key": true, "apikey": true, "private_key": true, "session_key": true,
	"master_key": true, "client_secret": true, "refresh_token": true,
	"access_token": true, "id_token": true,
}

// secretSuffixes catch the named variants — "smtp_password", "control.secret",
// "sealing_key" — without having to enumerate every one of them. Note that
// "key_id" does not end in any of these: a key id names a secret, it is not one,
// and it is exactly what an operator needs to see when signatures are rejected.
var secretSuffixes = []string{"_secret", "_token", "_password", "_key", ".secret", ".token", ".password", ".key"}

func redact(_ []string, a slog.Attr) slog.Attr {
	name := strings.ToLower(a.Key)
	if secretAttrs[name] {
		return slog.String(a.Key, redactedValue)
	}
	for _, suffix := range secretSuffixes {
		if strings.HasSuffix(name, suffix) {
			return slog.String(a.Key, redactedValue)
		}
	}
	return a
}

// teeSink writes every record to the console and to the file. It is not an
// io.MultiWriter: MultiWriter stops at the first sink that errors, which would
// mean a full disk silences the console too.
type teeSink struct {
	console io.Writer
	file    *rotator
	once    sync.Once
}

func (t *teeSink) Write(p []byte) (int, error) {
	n, err := t.console.Write(p)
	if _, ferr := t.file.Write(p); ferr != nil {
		// Once only: a failing disk fails on every record, and a message about
		// it per record would itself be the flood.
		t.once.Do(func() {
			fmt.Fprintf(os.Stderr, "logging: cannot write %s, continuing on the console only: %v\n", t.file.opts.File, ferr)
		})
	}
	return n, err
}
