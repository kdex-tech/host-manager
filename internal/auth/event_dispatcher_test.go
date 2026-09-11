package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

func hookTo(t *testing.T, name, url, events, mode string, extra map[string]string) *httpEventHook {
	t.Helper()
	d := map[string]string{"events": events, "mode": mode}
	for k, v := range extra {
		d[k] = v
	}
	h, err := NewHTTPEventHook(makeEventHookSecret(name, url, d))
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	return h
}

func TestGateLogin_NilDispatcherAllows(t *testing.T) {
	g := NewWithT(t)
	var d *EventDispatcher
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(Succeed())
}

func TestGateLogin_DenyShortCircuitsInNameOrder(t *testing.T) {
	g := NewWithT(t)
	var bHit atomic.Bool
	// "a" denies; "b" must never be called (name order, short-circuit).
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"reason":"nope"}`))
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		bHit.Store(true)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer b.Close()

	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "b", b.URL, "login", "enforcing", nil),
		hookTo(t, "a", a.URL, "login", "enforcing", nil),
	}, logr.Discard())

	err := d.GateLogin(context.Background(), EventPayload{Event: EventLogin, Subject: "x"})
	g.Expect(err).To(MatchError(ContainSubstring("nope")))
	g.Expect(bHit.Load()).To(BeFalse())
}

func TestGateLogin_TimeoutFailClosedByDefault(t *testing.T) {
	g := NewWithT(t)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer slow.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", slow.URL, "login", "enforcing", map[string]string{"timeout-ms": "10"}),
	}, logr.Discard())
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(HaveOccurred())
}

func TestGateLogin_TimeoutFailOpenWhenConfigured(t *testing.T) {
	g := NewWithT(t)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer slow.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", slow.URL, "login", "enforcing", map[string]string{"timeout-ms": "10", "failure-mode": "fail-open"}),
	}, logr.Discard())
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(Succeed())
}

func TestGateLogin_IgnoresAdvisoryHooks(t *testing.T) {
	g := NewWithT(t)
	var hit atomic.Bool
	adv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Store(true)
		_, _ = w.Write([]byte(`{"ok":false,"reason":"should not gate"}`))
	}))
	defer adv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", adv.URL, "login", "advisory", nil),
	}, logr.Discard())
	// advisory login hook must not gate; GateLogin sees no enforcing hooks.
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(Succeed())
}

func TestNotify_AsyncFireAndForget(t *testing.T) {
	g := NewWithT(t)
	var count atomic.Int32
	done := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
		done <- struct{}{}
	}))
	defer srv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "login-failed", "advisory", nil),
		hookTo(t, "b", srv.URL, "login-failed", "advisory", nil),
	}, logr.Discard())

	d.NotifyLoginFailed(context.Background(), EventPayload{Event: EventLoginFailed, Reason: "bad"})
	for i := 0; i < 2; i++ {
		g.Eventually(done, "2s").Should(Receive())
	}
	g.Expect(count.Load()).To(Equal(int32(2)))
}

func TestLogout_BarrierNeverRefuses(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":false,"reason":"try to refuse"}`)) // must be ignored
	}))
	defer slow.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", slow.URL, "logout", "enforcing", map[string]string{"timeout-ms": "5"}),
	}, logr.Discard())
	// Logout returns nothing and never blocks the caller from logging out.
	d.Logout(context.Background(), EventPayload{Event: EventLogout, Subject: "x"})
}

func TestGateLogin_MultipleEnforcingAllPass(t *testing.T) {
	g := NewWithT(t)
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ok.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", ok.URL, "login", "enforcing", nil),
		hookTo(t, "b", ok.URL, "login", "enforcing", nil),
	}, logr.Discard())
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(Succeed())
	_ = strings.TrimSpace // keep imports stable if edited
}

// TestSelecting_EnforcingModeIgnoredForNonEnforceableEvents is the Task 1 review
// nit: enforcingFor (and therefore the dispatcher's selection) must not treat a
// hook as enforcing for login-failed/session-refresh even when the hook's own
// mode is "enforcing" — only login/logout are enforceable events.
func TestSelecting_EnforcingModeIgnoredForNonEnforceableEvents(t *testing.T) {
	g := NewWithT(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	loginFailedHook := hookTo(t, "a", srv.URL, "login-failed", "enforcing", nil)
	sessionRefreshHook := hookTo(t, "b", srv.URL, "session-refresh", "enforcing", nil)
	d := NewEventDispatcher("h", []*httpEventHook{loginFailedHook, sessionRefreshHook}, logr.Discard())

	g.Expect(d.selecting(EventLoginFailed, true)).To(BeEmpty())
	g.Expect(d.selecting(EventLoginFailed, false)).To(ConsistOf(loginFailedHook))
	g.Expect(d.selecting(EventSessionRefresh, true)).To(BeEmpty())
	g.Expect(d.selecting(EventSessionRefresh, false)).To(ConsistOf(sessionRefreshHook))
}

// activeHookSecret builds an http-event-hook Secret annotated as the active
// key, as NewEventDispatcherFromSecrets expects to find it.
func activeHookSecret(name, url string, extra map[string]string) corev1.Secret {
	s := makeEventHookSecret(name, url, extra)
	s.Annotations = map[string]string{
		"kdex.dev/secret-type": HTTPEventHookSecretType,
		"kdex.dev/active-key":  "true",
	}
	return s
}

func TestNewEventDispatcherFromSecrets_FiltersByAnnotations(t *testing.T) {
	g := NewWithT(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	active := activeHookSecret("active", srv.URL, map[string]string{"events": "login"})

	inactive := activeHookSecret("inactive", srv.URL, map[string]string{"events": "login"})
	inactive.Annotations["kdex.dev/active-key"] = "false"

	wrongType := makeEventHookSecret("wrong-type", srv.URL, map[string]string{"events": "login"})
	wrongType.Annotations = map[string]string{
		"kdex.dev/secret-type": "ldap",
		"kdex.dev/active-key":  "true",
	}

	unrelated := corev1.Secret{}

	d, err := NewEventDispatcherFromSecrets("h", []corev1.Secret{active, inactive, wrongType, unrelated}, logr.Discard())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(d).ToNot(BeNil())
	g.Expect(d.hooks).To(HaveLen(1))
	g.Expect(d.hooks[0].name).To(Equal("active"))
}

func TestNewEventDispatcherFromSecrets_ReturnsFirstParseError(t *testing.T) {
	g := NewWithT(t)

	bad := activeHookSecret("bad", "", map[string]string{"events": "login"}) // missing url

	d, err := NewEventDispatcherFromSecrets("h", []corev1.Secret{bad}, logr.Discard())
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("url"))
	g.Expect(d).To(BeNil())
}

func TestNewEventDispatcherFromSecrets_NoMatchesReturnsUsableDispatcher(t *testing.T) {
	g := NewWithT(t)

	d, err := NewEventDispatcherFromSecrets("h", nil, logr.Discard())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(d).ToNot(BeNil())
	g.Expect(d.hooks).To(BeEmpty())
}
