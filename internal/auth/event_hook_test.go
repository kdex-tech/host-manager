package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func metaObjectMeta(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name} }

func makeEventHookSecret(name, url string, data map[string]string) corev1.Secret {
	d := map[string][]byte{
		"url":           []byte(url),
		"shared-secret": []byte(strings.Repeat("k", 32)),
	}
	for k, v := range data {
		d[k] = []byte(v)
	}
	return corev1.Secret{
		ObjectMeta: metaObjectMeta(name), // helper: see note below
		Data:       d,
	}
}

func TestNewHTTPEventHook_ParsesAndValidates(t *testing.T) {
	g := NewWithT(t)

	h, err := NewHTTPEventHook(makeEventHookSecret("h1", "https://x.example",
		map[string]string{"events": "login,logout", "mode": "enforcing", "timeout-ms": "1500", "failure-mode": "fail-open"}))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(h.events[EventLogin]).To(BeTrue())
	g.Expect(h.events[EventLogout]).To(BeTrue())
	g.Expect(h.mode).To(Equal(ModeEnforcing))
	g.Expect(h.failureMode).To(Equal(FailOpen))
	g.Expect(h.timeout.Milliseconds()).To(Equal(int64(1500)))
	g.Expect(h.name).To(Equal("h1"))
}

func TestNewHTTPEventHook_Rejects(t *testing.T) {
	g := NewWithT(t)

	// missing url
	_, err := NewHTTPEventHook(corev1.Secret{ObjectMeta: metaObjectMeta("h"), Data: map[string][]byte{"shared-secret": []byte(strings.Repeat("k", 32)), "events": []byte("login")}})
	g.Expect(err).To(MatchError(ContainSubstring("url")))

	// short shared-secret
	_, err = NewHTTPEventHook(corev1.Secret{ObjectMeta: metaObjectMeta("h"), Data: map[string][]byte{"url": []byte("https://x"), "shared-secret": []byte("short"), "events": []byte("login")}})
	g.Expect(err).To(MatchError(ContainSubstring("shared-secret")))

	// empty events
	_, err = NewHTTPEventHook(makeEventHookSecret("h", "https://x", map[string]string{"events": ""}))
	g.Expect(err).To(MatchError(ContainSubstring("events")))

	// unknown event token
	_, err = NewHTTPEventHook(makeEventHookSecret("h", "https://x", map[string]string{"events": "login,bogus"}))
	g.Expect(err).To(MatchError(ContainSubstring("bogus")))
}

func TestHTTPEventHook_Call_SignsAndSendsEnvelope(t *testing.T) {
	g := NewWithT(t)

	var gotSig, gotTs string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-K-CNAS-Event-Signature")
		gotTs = r.Header.Get("X-K-CNAS-Event-Timestamp")
		gotBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(eventHookResponse{OK: true})
	}))
	defer srv.Close()

	h, err := NewHTTPEventHook(makeEventHookSecret("h", srv.URL, map[string]string{"events": "login", "mode": "enforcing"}))
	g.Expect(err).ToNot(HaveOccurred())

	ok, _, err := h.call(context.Background(), EventPayload{Event: EventLogin, Subject: "alice"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ok).To(BeTrue())

	// signature must verify against the shared secret over ts + "." + body
	mac := hmac.New(sha256.New, []byte(strings.Repeat("k", 32)))
	mac.Write([]byte(gotTs))
	mac.Write([]byte("."))
	mac.Write(gotBody)
	g.Expect(gotSig).To(Equal(hex.EncodeToString(mac.Sum(nil))))

	var env EventPayload
	g.Expect(json.Unmarshal(gotBody, &env)).To(Succeed())
	g.Expect(env.Event).To(Equal(EventLogin))
	g.Expect(env.Subject).To(Equal("alice"))

	// The body's `timestamp` must equal the header/signed timestamp -- the
	// contract documented in README.md and the design spec ("matches the
	// signature timestamp"). Regression lock for the call() fix that used to
	// take a second, independent time.Now() reading for the header/HMAC.
	gotTsInt, err := strconv.ParseInt(gotTs, 10, 64)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(env.Timestamp).To(Equal(gotTsInt))
}

func TestHTTPEventHook_Call_OKFalseAndErrors(t *testing.T) {
	g := NewWithT(t)

	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(eventHookResponse{OK: false, Reason: "blocked"})
	}))
	defer deny.Close()
	h, _ := NewHTTPEventHook(makeEventHookSecret("h", deny.URL, map[string]string{"events": "login", "mode": "enforcing"}))
	ok, reason, err := h.call(context.Background(), EventPayload{Event: EventLogin})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ok).To(BeFalse())
	g.Expect(reason).To(Equal("blocked"))

	boom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer boom.Close()
	h2, _ := NewHTTPEventHook(makeEventHookSecret("h", boom.URL, map[string]string{"events": "login", "mode": "enforcing"}))
	_, _, err = h2.call(context.Background(), EventPayload{Event: EventLogin})
	g.Expect(err).To(HaveOccurred())
}
