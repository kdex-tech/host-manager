package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	. "github.com/onsi/gomega"
)

func TestTransferRecordRoundTrip(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{cacheManager: mgr}
	ctx := context.Background()

	rec := transferRecord{
		JTI:          "j1",
		Sub:          "alice",
		Entitlements: []string{"functions:/api/v1/files:read"},
		Target:       TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
	}
	g.Expect(hh.storeTransferRecord(ctx, "h1", rec, time.Minute)).ToNot(HaveOccurred())

	got, ok := hh.loadTransferRecord(ctx, "h1")
	g.Expect(ok).To(BeTrue())
	g.Expect(got).To(Equal(rec))

	_, ok = hh.loadTransferRecord(ctx, "missing")
	g.Expect(ok).To(BeFalse())
}

func TestNewTransferHandleUnique(t *testing.T) {
	g := NewWithT(t)
	a, err := newTransferHandle()
	g.Expect(err).ToNot(HaveOccurred())
	b, _ := newTransferHandle()
	g.Expect(a).ToNot(Equal(b))
	g.Expect(len(a)).To(BeNumerically(">=", 43)) // 32 bytes base64url (no pad)
}

func TestTransferBaseURL(t *testing.T) {
	g := NewWithT(t)
	r := httptest.NewRequest("POST", "https://ignored/api/v1/mcp", nil)
	r.Header.Set("X-Forwarded-Host", "dev.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	g.Expect(transferBaseURL(r)).To(Equal("https://dev.example"))
}

func TestTransferGet_RedispatchesAndDecrements(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)

	// A stub "function" registered on hh.Mux at the target's subtree. It reports
	// the entitlements the injected AuthContext carried and the path it saw.
	mux := http.NewServeMux()
	var sawPath string
	var sawEnts any
	mux.HandleFunc("GET /api/v1/files/", func(w http.ResponseWriter, r *http.Request) {
		ac, _ := auth.GetAuthContext(r.Context())
		sawPath = r.URL.Path
		sawEnts = ac["entitlements"]
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("FILEBYTES"))
	})

	hh := &HostHandler{cacheManager: mgr, Mux: mux}
	ctx := context.Background()
	c := mgr.GetCache("cap", cache.CacheOptions{Uncycled: true})
	_ = c.Set(ctx, "uses:j1", "1")
	_ = hh.storeTransferRecord(ctx, "h1", transferRecord{
		JTI:          "j1",
		Sub:          "alice",
		Entitlements: []string{"functions:/api/v1/files:read"},
		Target:       TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
	}, time.Minute)

	// First redemption succeeds and re-dispatches to the bound target.
	req := httptest.NewRequest("GET", "/-/transfer/h1", nil)
	req.SetPathValue("handle", "h1")
	rw := httptest.NewRecorder()
	hh.TransferGet(rw, req)
	g.Expect(rw.Code).To(Equal(http.StatusOK))
	g.Expect(rw.Body.String()).To(Equal("FILEBYTES"))
	g.Expect(sawPath).To(Equal("/api/v1/files/abc/content"))
	g.Expect(sawEnts).To(Equal([]string{"functions:/api/v1/files:read"}))

	// Second redemption is spent -> 410 (single-use).
	req2 := httptest.NewRequest("GET", "/-/transfer/h1", nil)
	req2.SetPathValue("handle", "h1")
	rw2 := httptest.NewRecorder()
	hh.TransferGet(rw2, req2)
	g.Expect(rw2.Code).To(Equal(http.StatusGone))
}

func TestTransferGet_UnknownHandle410(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{cacheManager: mgr, Mux: http.NewServeMux()}
	req := httptest.NewRequest("GET", "/-/transfer/nope", nil)
	req.SetPathValue("handle", "nope")
	rw := httptest.NewRecorder()
	hh.TransferGet(rw, req)
	g.Expect(rw.Code).To(Equal(http.StatusGone))
}

func TestTransferHandler_GatedOnPolicy(t *testing.T) {
	g := NewWithT(t)
	onMux := http.NewServeMux()
	(&HostHandler{authConfig: &auth.Config{MintTokenURLDelivery: true}}).transferHandler(onMux, nil)
	g.Expect(patternRegistered(onMux, "GET "+transferPath)).To(BeTrue())

	offMux := http.NewServeMux()
	(&HostHandler{authConfig: &auth.Config{MintTokenURLDelivery: false}}).transferHandler(offMux, nil)
	g.Expect(patternRegistered(offMux, "GET "+transferPath)).To(BeFalse())
}

func TestURLDelivery_EndToEnd(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)

	mux := http.NewServeMux()
	served := 0
	mux.HandleFunc("GET /api/v1/files/", func(w http.ResponseWriter, r *http.Request) {
		served++
		_, _ = w.Write([]byte("BYTES"))
	})

	hh := &HostHandler{authConfig: testURLAuthConfig(t), cacheManager: mgr, Mux: mux}
	hh.transferHandler(mux, nil) // register /-/transfer on the same mux

	// Mint a URL capability.
	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"functions:/api/v1/files:read"},
		MintTokenRequest{
			Entitlements: []string{"functions:/api/v1/files:read"},
			Delivery:     "url",
			Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
		}, "https://dev.example")
	g.Expect(err).ToNot(HaveOccurred())
	path := strings.TrimPrefix(res.URL, "https://dev.example")

	// Redeem through the registered route: streams the bytes once.
	rw := httptest.NewRecorder()
	mux.ServeHTTP(rw, httptest.NewRequest("GET", path, nil))
	g.Expect(rw.Code).To(Equal(http.StatusOK))
	g.Expect(rw.Body.String()).To(Equal("BYTES"))
	g.Expect(served).To(Equal(1))

	// Second redeem: single-use spent -> 410, backend not hit again.
	rw2 := httptest.NewRecorder()
	mux.ServeHTTP(rw2, httptest.NewRequest("GET", path, nil))
	g.Expect(rw2.Code).To(Equal(http.StatusGone))
	g.Expect(served).To(Equal(1))
}

func TestBearerDelivery_Unchanged(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"functions:/api/v1/files:read"},
		MintTokenRequest{Entitlements: []string{"functions:/api/v1/files:read"}}, "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Token).ToNot(BeEmpty())
	g.Expect(res.URL).To(BeEmpty())
}

func TestLoadTransferRecord_CorruptJSON(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{cacheManager: mgr}
	ctx := context.Background()
	c := mgr.GetCache("cap", cache.CacheOptions{Uncycled: true})
	_ = c.Set(ctx, transferKeyPrefix+"bad", "{not json")
	_, ok := hh.loadTransferRecord(ctx, "bad")
	g.Expect(ok).To(BeFalse()) // fail-closed on decode error
}

func TestTransferGet_WrongMethod410(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{cacheManager: mgr, Mux: http.NewServeMux()}
	ctx := context.Background()
	c := mgr.GetCache("cap", cache.CacheOptions{Uncycled: true})
	_ = c.Set(ctx, "uses:jm", "1")
	_ = hh.storeTransferRecord(ctx, "hm", transferRecord{
		JTI: "jm", Sub: "alice",
		Entitlements: []string{"functions:/api/v1/files:read"},
		Target:       TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
	}, time.Minute)
	req := httptest.NewRequest("POST", "/-/transfer/hm", nil) // method mismatch vs stored GET
	req.SetPathValue("handle", "hm")
	rw := httptest.NewRecorder()
	hh.TransferGet(rw, req)
	g.Expect(rw.Code).To(Equal(http.StatusGone))
}

func TestTransferGet_NilMux410(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{cacheManager: mgr, Mux: nil} // nil mux -> fail-closed
	ctx := context.Background()
	c := mgr.GetCache("cap", cache.CacheOptions{Uncycled: true})
	_ = c.Set(ctx, "uses:jn", "1")
	_ = hh.storeTransferRecord(ctx, "hn", transferRecord{
		JTI: "jn", Sub: "alice",
		Entitlements: []string{"functions:/api/v1/files:read"},
		Target:       TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
	}, time.Minute)
	req := httptest.NewRequest("GET", "/-/transfer/hn", nil)
	req.SetPathValue("handle", "hn")
	rw := httptest.NewRecorder()
	hh.TransferGet(rw, req)
	g.Expect(rw.Code).To(Equal(http.StatusGone))
}
