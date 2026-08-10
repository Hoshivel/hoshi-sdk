package lifecycle

import (
	"runtime/debug"
	"sync"
)

// Build describes the commit this binary was built from.
//
// The Go toolchain stamps this into every binary built from a version-controlled
// working tree, so a deployed artefact can answer "which commit are you?"
// without anyone having to inject it at build time. Stripping flags do not
// remove it: -ldflags "-s -w" drops the symbol table and DWARF, -trimpath drops
// file paths, and neither touches the build-info section.
//
// Revision is empty when the binary was not built from a repository — `go run`
// on a bare directory, or a build from an unpacked source archive. That is
// reported honestly rather than filled in with a placeholder: an unknown
// revision and a wrong one are very different things to whoever is reading a
// log at three in the morning.
type Build struct {
	// Revision is the full commit hash, or "" when unknown.
	Revision string
	// Time is the commit timestamp in RFC 3339, or "" when unknown.
	Time string
	// Modified reports whether the working tree had uncommitted changes at
	// build time. A true here means the revision alone does not identify what
	// is running.
	Modified bool
}

var (
	buildOnce sync.Once
	buildInfo Build
)

// BuildOf returns the build stamp of the running binary.
//
// It is read once and cached: the answer cannot change while the process is
// alive, and callers tend to want it on a startup path where an extra read of
// the binary's own metadata is pure cost.
func BuildOf() Build {
	buildOnce.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				buildInfo.Revision = s.Value
			case "vcs.time":
				buildInfo.Time = s.Value
			case "vcs.modified":
				buildInfo.Modified = s.Value == "true"
			}
		}
	})
	return buildInfo
}

// Short is the form to put in a log line: an abbreviated revision, with a
// "+dirty" suffix when the working tree was not clean.
//
// It returns "unknown" rather than an empty string, because an empty value in a
// structured log reads as "the field is not set" — and "we do not know which
// commit this is" is a fact worth stating out loud.
func (b Build) Short() string {
	if b.Revision == "" {
		return "unknown"
	}
	short := b.Revision
	if len(short) > 12 {
		short = short[:12]
	}
	if b.Modified {
		return short + "+dirty"
	}
	return short
}

// LogAttrs is the build stamp as alternating key/value pairs, ready to append
// to a structured log call:
//
//	log.Info("starting", append([]any{"addr", addr}, lifecycle.BuildOf().LogAttrs()...)...)
//
// Only known fields are included, so a binary built outside a repository logs
// build=unknown and nothing else, instead of a row of empty strings.
func (b Build) LogAttrs() []any {
	attrs := []any{"build", b.Short()}
	if b.Time != "" {
		attrs = append(attrs, "built_at", b.Time)
	}
	return attrs
}
