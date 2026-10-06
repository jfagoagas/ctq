package ct

import (
	"context"
	"fmt"
	"io"
)

// Level ranks a trace event.
type Level int

const (
	LevelInfo Level = iota
	LevelWarn
	LevelError
)

// Tracer receives what each search source is doing: connections, requests,
// retries, pages, fallbacks. It runs on the searching goroutine and must not block.
type Tracer func(source string, level Level, msg string)

type (
	tracerKey struct{}
	sourceKey struct{}
)

// WithTracer makes searches run with ctx report to t.
func WithTracer(ctx context.Context, t Tracer) context.Context {
	return context.WithValue(ctx, tracerKey{}, t)
}

// withSource names the source that events from ctx belong to. The HTTP client
// doesn't know which source it works for, so the name travels in the context.
func withSource(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, sourceKey{}, name)
}

// Trace reports an event for whichever source ctx belongs to. Without a tracer it does nothing.
func Trace(ctx context.Context, level Level, format string, args ...any) {
	t, _ := ctx.Value(tracerKey{}).(Tracer)
	if t == nil {
		return
	}
	src, _ := ctx.Value(sourceKey{}).(string)
	t(src, level, fmt.Sprintf(format, args...))
}

func warnf(w io.Writer, format string, args ...any) {
	if w != nil {
		fmt.Fprintf(w, "ctq: "+format+"\n", args...)
	}
}

// searchWarnf is warnf for search sources: the warning is also traced.
func searchWarnf(ctx context.Context, w io.Writer, format string, args ...any) {
	Trace(ctx, LevelWarn, format, args...)
	warnf(w, format, args...)
}
