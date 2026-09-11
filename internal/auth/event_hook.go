package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

const (
	HTTPEventHookSecretType = "http-event-hook"
	defaultEventHookTimeout = 2 * time.Second
)

type EventType string

const (
	EventLogin          EventType = "login"
	EventLogout         EventType = "logout"
	EventLoginFailed    EventType = "login-failed"
	EventSessionRefresh EventType = "session-refresh"
)

// enforceableEvents are the only events for which mode=enforcing is honored.
var enforceableEvents = map[EventType]bool{EventLogin: true, EventLogout: true}

func knownEvent(e EventType) bool {
	switch e {
	case EventLogin, EventLogout, EventLoginFailed, EventSessionRefresh:
		return true
	}
	return false
}

type HookMode string

const (
	ModeAdvisory  HookMode = "advisory"
	ModeEnforcing HookMode = "enforcing"
)

type FailureMode string

const (
	FailOpen   FailureMode = "fail-open"
	FailClosed FailureMode = "fail-closed"
)

// EventPayload is the JSON envelope POSTed to a hook. Field presence varies by
// event (see the design spec); omitempty keeps absent context out of the body.
type EventPayload struct {
	Event        EventType      `json:"event"`
	Timestamp    int64          `json:"timestamp"`
	Host         string         `json:"host"`
	Subject      string         `json:"subject"`
	AuthMethod   string         `json:"auth_method,omitempty"`
	ClientID     string         `json:"client_id,omitempty"`
	Scope        string         `json:"scope,omitempty"`
	Claims       map[string]any `json:"claims,omitempty"`
	Roles        []string       `json:"roles,omitempty"`
	Entitlements []string       `json:"entitlements,omitempty"`
	SessionID    string         `json:"session_id,omitempty"`
	Reason       string         `json:"reason,omitempty"`
}

type eventHookResponse struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

type httpEventHook struct {
	name         string
	url          string
	sharedSecret []byte
	events       map[EventType]bool
	mode         HookMode
	failureMode  FailureMode // "" = unset -> per-event default resolved in the dispatcher
	timeout      time.Duration
	client       *http.Client
}

func NewHTTPEventHook(secret corev1.Secret) (*httpEventHook, error) {
	url := string(secret.Data["url"])
	if url == "" {
		return nil, errors.New("http-event-hook Secret missing required 'url' data field")
	}

	sharedSecret := secret.Data["shared-secret"]
	if len(sharedSecret) < minSharedSecretBytes {
		return nil, fmt.Errorf("http-event-hook Secret 'shared-secret' must be at least %d bytes (got %d)",
			minSharedSecretBytes, len(sharedSecret))
	}

	events := map[EventType]bool{}
	for _, tok := range strings.Split(string(secret.Data["events"]), ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		et := EventType(tok)
		if !knownEvent(et) {
			return nil, fmt.Errorf("http-event-hook Secret 'events' has unknown event %q", tok)
		}
		events[et] = true
	}
	if len(events) == 0 {
		return nil, errors.New("http-event-hook Secret 'events' must list at least one event")
	}

	mode := ModeAdvisory
	if raw := string(secret.Data["mode"]); raw != "" {
		switch HookMode(raw) {
		case ModeAdvisory, ModeEnforcing:
			mode = HookMode(raw)
		default:
			return nil, fmt.Errorf("http-event-hook Secret 'mode' must be advisory or enforcing (got %q)", raw)
		}
	}

	var failureMode FailureMode
	if raw := string(secret.Data["failure-mode"]); raw != "" {
		switch FailureMode(raw) {
		case FailOpen, FailClosed:
			failureMode = FailureMode(raw)
		default:
			return nil, fmt.Errorf("http-event-hook Secret 'failure-mode' must be fail-open or fail-closed (got %q)", raw)
		}
	}

	timeout := defaultEventHookTimeout
	if raw := string(secret.Data["timeout-ms"]); raw != "" {
		ms, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("http-event-hook Secret 'timeout-ms' is not a valid integer: %w", err)
		}
		timeout = time.Duration(ms) * time.Millisecond
	}

	return &httpEventHook{
		name:         secret.Name,
		url:          url,
		sharedSecret: sharedSecret,
		events:       events,
		mode:         mode,
		failureMode:  failureMode,
		timeout:      timeout,
		client:       &http.Client{Timeout: timeout},
	}, nil
}

// enforcingFor reports whether this hook enforces (sync-gates) the given event.
// Only login/logout are enforceable; everything else is always advisory.
func (h *httpEventHook) enforcingFor(e EventType) bool {
	return h.mode == ModeEnforcing && enforceableEvents[e]
}

// call POSTs the HMAC-signed envelope and returns the (ok, reason) response.
// A transport/status/decode failure returns a non-nil err; a clean ok=false is
// err==nil with ok==false.
func (h *httpEventHook) call(ctx context.Context, payload EventPayload) (bool, string, error) {
	// The dispatcher normally stamps Timestamp before calling in (GateLogin /
	// NotifyLoginSuccess / NotifySessionRefresh / Logout all set it). A caller
	// that reaches call() directly without going through the dispatcher (unit
	// tests included) may leave it at the zero value, so it is filled in here
	// as the single source of truth -- this is the ONLY time reading in this
	// method. The body's `timestamp` field and the signed/header timestamp
	// must be the same value (see README/design spec: "matches the signature
	// timestamp"), so both are derived from payload.Timestamp after this
	// point rather than each taking their own reading.
	if payload.Timestamp == 0 {
		payload.Timestamp = time.Now().UnixMilli()
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, "", fmt.Errorf("httpEventHook: marshal: %w", err)
	}
	ts := strconv.FormatInt(payload.Timestamp, 10)
	sig := computeSignature(h.sharedSecret, ts, body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return false, "", fmt.Errorf("httpEventHook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-K-CNAS-Event-Timestamp", ts)
	req.Header.Set("X-K-CNAS-Event-Signature", sig)

	resp, err := h.client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("httpEventHook: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("httpEventHook: server returned status %d", resp.StatusCode)
	}

	var parsed eventHookResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return false, "", fmt.Errorf("httpEventHook: decode response: %w", err)
	}
	return parsed.OK, parsed.Reason, nil
}

// sortHooksByName gives enforcing evaluation a deterministic order.
func sortHooksByName(hooks []*httpEventHook) {
	sort.Slice(hooks, func(i, j int) bool { return hooks[i].name < hooks[j].name })
}
