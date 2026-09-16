package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
)

// ErrLoginHookDenied is returned by GateLogin when an enforcing login hook
// denies the login (ok=false, or a fail-closed transport failure).
var ErrLoginHookDenied = errors.New("login denied by event hook")

// eventDispatcherLoggerName is attached (via WithName) to the logger of every
// dispatcher, so all auth event-hook log lines share one filterable name
// regardless of which controller owns the dispatcher.
const eventDispatcherLoggerName = "auth-event-hook"

// EventDispatcher owns the parsed hooks for one host and emits lifecycle events.
// A nil *EventDispatcher is valid: every method is a no-op (GateLogin allows).
type EventDispatcher struct {
	host  string
	hooks []*httpEventHook // sorted by name
	log   logr.Logger
}

func NewEventDispatcher(host string, hooks []*httpEventHook, log logr.Logger) *EventDispatcher {
	sortHooksByName(hooks)
	return &EventDispatcher{host: host, hooks: hooks, log: log.WithName(eventDispatcherLoggerName)}
}

// NewEventDispatcherFromSecrets filters secrets down to the active
// http-event-hook Secrets (kdex.dev/secret-type == HTTPEventHookSecretType
// and kdex.dev/active-key == "true"), parses each into an httpEventHook, and
// wraps the result in an EventDispatcher. Returns the first parse error
// encountered, if any. httpEventHook is unexported, so this is the only way
// a caller outside the auth package can build a dispatcher from Secrets.
func NewEventDispatcherFromSecrets(host string, secrets []corev1.Secret, log logr.Logger) (*EventDispatcher, error) {
	var hooks []*httpEventHook
	for _, s := range secrets {
		if s.Annotations["kdex.dev/secret-type"] != HTTPEventHookSecretType ||
			s.Annotations["kdex.dev/active-key"] != "true" {
			continue
		}
		h, err := NewHTTPEventHook(s)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, h)
	}
	return NewEventDispatcher(host, hooks, log), nil
}

// bgTimeout derives a background context bounded by the hook's own timeout, so
// neither the request's cancellation nor a slow hook can hang or abort work.
func bgTimeout(h *httpEventHook) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), h.timeout)
}

// eventKV builds the contextual key/value pairs shared by every event-hook log
// line: the event plus the identity/session context that says whose lifecycle
// event this is (event, host, subject, auth_method a.k.a. provider, client_id,
// scope, session_id). Bulky/sensitive fields (claims, roles, entitlements) are
// deliberately excluded, and empty fields are dropped so a line carries only the
// context the event actually has. `extra` appends call-site pairs (hook, reason).
func eventKV(p EventPayload, extra ...any) []any {
	kv := make([]any, 0, 14+len(extra))
	kv = append(kv, "event", string(p.Event))
	if p.Host != "" {
		kv = append(kv, "host", p.Host)
	}
	if p.Subject != "" {
		kv = append(kv, "subject", p.Subject)
	}
	if p.AuthMethod != "" {
		kv = append(kv, "auth_method", p.AuthMethod)
	}
	if p.ClientID != "" {
		kv = append(kv, "client_id", p.ClientID)
	}
	if p.Scope != "" {
		kv = append(kv, "scope", p.Scope)
	}
	if p.SessionID != "" {
		kv = append(kv, "session_id", p.SessionID)
	}
	return append(kv, extra...)
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

// HasEnforcingLogin reports whether any configured hook is an enforcing gate for
// the login event. It is the trigger for the #206 post-gate enrichment: only a
// deployment that actually runs an enforcing login gate can provision a subject
// during login, so this keeps the enrichment (and its extra backend resolve) off
// the mint path for every other deployment. Nil-safe (a nil dispatcher enforces
// nothing).
func (d *EventDispatcher) HasEnforcingLogin() bool {
	if d == nil {
		return false
	}
	return len(d.selecting(EventLogin, true)) > 0
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
				d.log.Error(err, "enforcing login hook errored; failing open", eventKV(p, "hook", h.name)...)
				continue
			}
			d.log.Error(err, "enforcing login hook errored; failing closed", eventKV(p, "hook", h.name)...)
			return fmt.Errorf("%w: %s", ErrLoginHookDenied, "hook unavailable")
		}
		if !ok {
			if reason == "" {
				reason = "denied"
			}
			d.log.V(2).Info("enforcing login hook denied login", eventKV(p, "hook", h.name, "reason", reason)...)
			return fmt.Errorf("%w: %s", ErrLoginHookDenied, reason)
		}
		d.log.V(2).Info("enforcing login hook allowed login", eventKV(p, "hook", h.name)...)
	}
	d.log.V(2).Info("all enforcing login hooks passed", eventKV(p)...)
	return nil
}

func (d *EventDispatcher) fireAsync(p EventPayload, hooks []*httpEventHook) {
	for _, h := range hooks {
		go func() {
			cctx, cancel := bgTimeout(h)
			defer cancel()
			if _, _, err := h.call(cctx, p); err != nil {
				d.log.Error(err, "async event hook failed", eventKV(p, "hook", h.name)...)
				return
			}
			d.log.V(2).Info("async event hook fired", eventKV(p, "hook", h.name)...)
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
			d.log.Error(err, "enforcing logout barrier failed; proceeding with logout", eventKV(p, "hook", h.name)...)
		} else {
			d.log.V(2).Info("enforcing logout barrier passed", eventKV(p, "hook", h.name)...)
		}
		cancel()
	}
	d.fireAsync(p, d.selecting(EventLogout, false))
}
