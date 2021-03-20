package oonet

import "context"

// contextMonitorKey is the key used to recognise within a
// specific context which is the Monitor.
type contextMonitorKey struct{}

// WithMonitor returns a copy of ctx with the configured instance
// of Monitor as the monitor. This function will return the
// original context if it's passed a nil Monitor.
func WithMonitor(ctx context.Context, monitor Monitor) context.Context {
	if monitor == nil {
		return ctx
	}
	return context.WithValue(ctx, contextMonitorKey{}, monitor)
}

// ContextMonitor returns the Monitor associated with
// this instance of the context. If there is no Monitor
// associated with the context, this function will return
// a do-nothing instance of Monitor instead.
func ContextMonitor(ctx context.Context) Monitor {
	monitor, _ := ctx.Value(contextMonitorKey{}).(Monitor)
	if monitor == nil {
		return &monitorDefault{}
	}
	return monitor
}
