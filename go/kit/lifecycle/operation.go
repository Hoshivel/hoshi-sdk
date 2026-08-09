package lifecycle

import "time"

// Operation times one unit of work and reports how it ended.
//
// It exists so a failure carries the context of what was being attempted rather
// than only the error text: "open database" plus the path and the elapsed time
// is diagnosable, `dial tcp: connection refused` on its own is not. Successes
// are debug-level, so the record of what a healthy service is doing appears
// exactly when debug mode is on and costs nothing when it is not.
type Operation struct {
	log     Logger
	name    string
	started time.Time
	attrs   []any
}

// Begin starts recording an operation.
func Begin(log Logger, name string, attrs ...any) *Operation {
	op := &Operation{log: log, name: name, started: time.Now(), attrs: attrs}
	log.Debug("started", append([]any{"op", name}, attrs...)...)
	return op
}

// OK ends the operation successfully.
func (o *Operation) OK(attrs ...any) {
	o.log.Debug("finished", o.fields(nil, attrs)...)
}

// Fail ends the operation with an error and returns that same error, so a call
// site can log and return in one expression:
//
//	return op.Fail(err)
func (o *Operation) Fail(err error, attrs ...any) error {
	o.log.Error("failed", o.fields(err, attrs)...)
	return err
}

// End is Fail or OK depending on err, for a deferred call.
func (o *Operation) End(err error, attrs ...any) {
	if err != nil {
		_ = o.Fail(err, attrs...)
		return
	}
	o.OK(attrs...)
}

func (o *Operation) fields(err error, extra []any) []any {
	fields := []any{"op", o.name, "took", time.Since(o.started).Round(time.Millisecond).String()}
	fields = append(fields, o.attrs...)
	fields = append(fields, extra...)
	if err != nil {
		fields = append(fields, "error", err)
	}
	return fields
}
