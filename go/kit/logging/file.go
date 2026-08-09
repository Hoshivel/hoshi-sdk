package logging

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// rotator writes to a file, rolls it aside when it grows past MaxSizeMB or when
// the day turns, and deletes the history that is older or more numerous than
// asked for.
//
// It is written here rather than pulled in as a dependency because it is a
// couple of hundred lines, and because these services' dependency lists are
// short on purpose.
//
// Rolling on the day boundary as well as on size is what makes "keep logs for N
// days" mean anything. With size-only rolling a quiet service never rolls, so
// nothing is ever old enough to delete and one file grows without bound — the
// retention window would be configured, honoured to the letter, and have no
// effect whatsoever.
type rotator struct {
	opts Options

	mu   sync.Mutex
	file *os.File
	size int64
	// day is the UTC day the current file belongs to. For a file that already
	// has content it comes from the modification time, so one left over from
	// yesterday rolls on the first write rather than accumulating two days in
	// one archive. For an empty file it stays zero until something is actually
	// written: an empty file belongs to no day, and dating it at open would
	// make a service started at 23:59 roll a file with nothing in it.
	day time.Time

	// now is a seam for tests; nil means time.Now.
	now func() time.Time
}

// Permissions: logs name accounts, addresses and remote hosts. That is not
// world-readable material, and a log directory that anyone can read is a way to
// learn who uses a service without having access to it.
const (
	logFileMode = 0o600
	logDirMode  = 0o700
)

// rollStamp is the suffix appended to a rolled-aside file. It sorts
// lexically in chronological order, which is what makes the history readable.
const rollStamp = "20060102T150405"

func newRotator(o Options) (*rotator, error) {
	if dir := filepath.Dir(o.File); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, logDirMode); err != nil {
			return nil, fmt.Errorf("log.file: %w", err)
		}
	}
	r := &rotator{opts: o}
	if err := r.open(); err != nil {
		return nil, err
	}
	// Prune once at startup too. A service that was down for longer than its
	// retention window would otherwise keep every file it had until it happened
	// to roll again.
	r.prune()
	return r, nil
}

func (r *rotator) open() error {
	file, err := os.OpenFile(r.opts.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFileMode)
	if err != nil {
		return fmt.Errorf("log.file: %w", err)
	}
	r.file = file
	r.size = 0
	r.day = time.Time{}
	if info, err := file.Stat(); err == nil {
		r.size = info.Size()
		if r.size > 0 {
			r.day = truncateDay(info.ModTime())
		}
	}
	return nil
}

func (r *rotator) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func (r *rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	now := r.clock()
	today := truncateDay(now)
	overSize := r.opts.MaxSizeMB > 0 && r.size > 0 &&
		r.size+int64(len(p)) > int64(r.opts.MaxSizeMB)<<20
	dayTurned := r.size > 0 && !r.day.IsZero() && !today.Equal(r.day)
	if overSize || dayTurned {
		if err := r.roll(now); err != nil {
			return 0, err
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	if r.day.IsZero() {
		r.day = today
	}
	return n, err
}

// roll renames the current file out of the way and starts a new one. The old
// name carries the moment it was closed, which is what makes the history
// readable in order.
func (r *rotator) roll(now time.Time) error {
	if err := r.file.Close(); err != nil {
		return err
	}
	r.file = nil
	if err := os.Rename(r.opts.File, r.rolledName(now)); err != nil {
		// A rename that fails must not take the service's logging with it: the
		// file is reopened and writing continues, oversized.
		_ = r.open()
		return err
	}
	if err := r.open(); err != nil {
		return err
	}
	r.prune()
	return nil
}

// rolledName is the archive name for a roll happening at now, made unique so
// that two rolls in the same second — a burst against a small max_size_mb — do
// not have the second one overwrite the first.
func (r *rotator) rolledName(now time.Time) string {
	base := r.opts.File + "." + now.UTC().Format(rollStamp)
	name := base
	for i := 1; i < 1000; i++ {
		if _, err := os.Stat(name); errors.Is(err, fs.ErrNotExist) {
			break
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
	return name
}

// roll is one archived file, with the time its name says it was archived.
type rolled struct {
	path string
	at   time.Time
}

// prune enforces the retention window and the file cap. Errors are ignored on
// purpose: this is housekeeping, and a log that cannot tidy up is still a log.
func (r *rotator) prune() {
	if r.opts.RetainDays <= 0 && r.opts.MaxFiles <= 0 {
		return
	}
	found := r.rolls()
	if r.opts.RetainDays > 0 {
		cutoff := r.clock().Add(-time.Duration(r.opts.RetainDays) * 24 * time.Hour)
		kept := found[:0]
		for _, f := range found {
			if f.at.Before(cutoff) {
				_ = os.Remove(f.path)
				continue
			}
			kept = append(kept, f)
		}
		found = kept
	}
	if r.opts.MaxFiles > 0 && len(found) > r.opts.MaxFiles {
		// rolls() sorts oldest first, so the excess is at the front.
		for _, f := range found[:len(found)-r.opts.MaxFiles] {
			_ = os.Remove(f.path)
		}
	}
}

// rolls lists this file's archives, oldest first.
func (r *rotator) rolls() []rolled {
	dir := filepath.Dir(r.opts.File)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	prefix := filepath.Base(r.opts.File) + "."
	var out []rolled
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		at, ok := rolledAt(strings.TrimPrefix(e.Name(), prefix))
		if !ok {
			continue
		}
		out = append(out, rolled{path: filepath.Join(dir, e.Name()), at: at})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })
	return out
}

// rolledAt reads the archive time out of a name this rotator produced. The name
// is the source of truth rather than the modification time, which any copy,
// restore or backup tool is free to rewrite.
func rolledAt(suffix string) (time.Time, bool) {
	// Drop the disambiguating "-1", "-2" of a same-second roll.
	if i := strings.IndexByte(suffix, '-'); i >= 0 {
		suffix = suffix[:i]
	}
	at, err := time.ParseInLocation(rollStamp, suffix, time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

func (r *rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func truncateDay(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}
