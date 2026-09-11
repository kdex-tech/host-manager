package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
)

// ErrLoginHookDenied is returned by GateLogin when an enforcing login hook
// denies the login (ok=false, or a fail-closed transport failure).
var ErrLoginHookDenied = errors.New("login denied by event hook")

// EventDispatcher owns the parsed hooks for one host and emits lifecycle events.
// A nil *EventDispatcher is valid: every method is a no-op (GateLogin allows).
type EventDispatcher struct {
	host  string
	hooks []*httpEventHook // sorted by name
	log   logr.Logger
}

func NewEventDispatcher(host string, hooks []*httpEventHook, log logr.Logger) *EventDispatcher {
	sortHooksByName(hooks)
	return &EventDispatcher{host: host, hooks: hooks, log: log}
}

// bgTimeout derives a background context bounded by the hook's own timeout, so
// neither the request's cancellation nor a slow hook can hang or abort work.
func bgTimeout(h *httpEventHook) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), h.timeout)
}

func (d *EventDispatcher) selecting(e EventType, enforcing bool) []*httpEventHook {
	var out []*httpEventHook
	for _, h := range d.hooks {
		if !h.events[e] {
			continue
		}
		if enforcing != h.enforcingFor(e) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// GateLogin runs the enforcing login hooks in name order and denies on the first
// ok=false (or, per failure-mode, a transport error). Nil-safe.
func (d *EventDispatcher) GateLogin(ctx context.Context, p EventPayload) error {
	if d == nil {
		return nil
	}
	p.Host = d.host
	p.Timestamp = time.Now().UnixMilli()
	for _, h := range d.selecting(EventLogin, true) {
		cctx, cancel := bgTimeout(h)
		ok, reason, err := h.call(cctx, p)
		cancel()
		if err != nil {
			// login default is fail-closed; only an explicit fail-open allows.
			if h.failureMode == FailOpen {
				d.log.Error(err, "enforcing login hook errored; failing open", "hook", h.name)
				continue
			}
			d.log.Error(err, "enforcing login hook errored; failing closed", "hook", h.name)
			return fmt.Errorf("%w: %s", ErrLoginHookDenied, "hook unavailable")
		}
		if !ok {
			if reason == "" {
				reason = "denied"
			}
			return fmt.Errorf("%w: %s", ErrLoginHookDenied, reason)
		}
	}
	return nil
}

func (d *EventDispatcher) fireAsync(p EventPayload, hooks []*httpEventHook) {
	for _, h := range hooks {
		h := h
		go func() {
			cctx, cancel := bgTimeout(h)
			defer cancel()
			if _, _, err := h.call(cctx, p); err != nil {
				d.log.Error(err, "async event hook failed", "hook", h.name, "event", string(p.Event))
			}
		}()
	}
}

func (d *EventDispatcher) NotifyLoginSuccess(ctx context.Context, p EventPayload) {
	if d == nil {
		return
	}
	p.Host, p.Timestamp = d.host, time.Now().UnixMilli()
	d.fireAsync(p, d.selecting(EventLogin, false))
}

func (d *EventDispatcher) NotifyLoginFailed(ctx context.Context, p EventPayload) {
	if d == nil {
		return
	}
	p.Host, p.Timestamp = d.host, time.Now().UnixMilli()
	// login-failed is async-only, so both advisory and (ignored) enforcing hooks
	// that subscribe to it fire async: select every hook subscribed to the event.
	var all []*httpEventHook
	for _, h := range d.hooks {
		if h.events[EventLoginFailed] {
			all = append(all, h)
		}
	}
	d.fireAsync(p, all)
}

func (d *EventDispatcher) NotifySessionRefresh(ctx context.Context, p EventPayload) {
	if d == nil {
		return
	}
	p.Host, p.Timestamp = d.host, time.Now().UnixMilli()
	var all []*httpEventHook
	for _, h := range d.hooks {
		if h.events[EventSessionRefresh] {
			all = append(all, h)
		}
	}
	d.fireAsync(p, all)
}

// Logout runs enforcing-logout hooks as sequential barriers (blocking up to each
// hook's timeout) but NEVER refuses the logout, then fires advisory-logout hooks
// async. Nil-safe.
func (d *EventDispatcher) Logout(ctx context.Context, p EventPayload) {
	if d == nil {
		return
	}
	p.Host, p.Timestamp = d.host, time.Now().UnixMilli()
	for _, h := range d.selecting(EventLogout, true) {
		cctx, cancel := bgTimeout(h)
		if _, _, err := h.call(cctx, p); err != nil {
			d.log.Error(err, "enforcing logout barrier failed; proceeding with logout", "hook", h.name)
		}
		cancel()
	}
	d.fireAsync(p, d.selecting(EventLogout, false))
}
