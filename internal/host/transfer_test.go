package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
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
	(&HostHandler{authConfig: &auth.Config{MintTokenURLDelivery: true}}).transferHandler(onMux, map[string]ko.PathInfo{})
	g.Expect(patternRegistered(onMux, "GET "+transferPath)).To(BeTrue())

	offMux := http.NewServeMux()
	(&HostHandler{authConfig: &auth.Config{MintTokenURLDelivery: false}}).transferHandler(offMux, map[string]ko.PathInfo{})
	g.Expect(patternRegistered(offMux, "GET "+transferPath)).To(BeFalse())
}

// The redemption route is the one /-/ route that published no PathInfo, so an
// agent reading /-/openapi never learned the mechanism exists (#185).
func TestTransferHandler_PublishesOpenAPIPath(t *testing.T) {
	g := NewWithT(t)

	on := map[string]ko.PathInfo{}
	(&HostHandler{authConfig: &auth.Config{MintTokenURLDelivery: true}}).
		transferHandler(http.NewServeMux(), on)

	info, ok := on[transferPath]
	g.Expect(ok).To(BeTrue(), "url delivery on -> the redemption route must be documented")
	g.Expect(info.Type).To(Equal(ko.SystemPathType))

	item, ok := info.API.Paths[transferPath]
	g.Expect(ok).To(BeTrue())
	g.Expect(item.Get).ToNot(BeNil())
	g.Expect(item.Get.OperationID).To(Equal("transfer-redeem-get"))

	// The 410 is the anti-enumeration catch-all: a recipient cannot tell spent
	// from expired from unknown, and the contract should say so.
	g.Expect(item.Get.Responses.Status(http.StatusGone)).ToNot(BeNil())
	// Sending an Authorization header gets the request rejected by the outer
	// middleware before redemption -- counter-intuitive enough to document.
	g.Expect(item.Get.Responses.Status(http.StatusUnauthorized)).ToNot(BeNil())
	// The handle IS the credential; the route carries no security requirement.
	g.Expect(item.Get.Security).To(BeNil())

	off := map[string]ko.PathInfo{}
	(&HostHandler{authConfig: &auth.Config{MintTokenURLDelivery: false}}).
		transferHandler(http.NewServeMux(), off)
	g.Expect(off).To(BeEmpty(), "url delivery off -> no route exists, so nothing to document")
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
	hh.transferHandler(mux, map[string]ko.PathInfo{}) // register /-/transfer on the same mux

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

// TestURLDelivery_ThroughRealProxy exercises URL-delivery redemption through
// the REAL reverseProxyHandler (identity gate + FAT re-mint + header
// allowlist) rather than a stub function handler — all other redemption
// tests in this file stub the target handler, leaving that leg untested. It
// also proves FIX #1 (recipient-header stripping in TransferGet): a recipient
// cannot smuggle its own non-allowlisted headers (X-Api-Token, an arbitrary
// X-Vector-Store-Id) into the forwarded request, yet an allowlisted header
// (Range) still reaches the backend. (The forwarded Authorization is the
// minted FAT rather than the recipient's token because the proxy re-mints it
// unconditionally — that is FAT re-mint, a separate protection from #1's
// stripping.) See kdex-tech/host-manager#151.
func TestURLDelivery_ThroughRealProxy(t *testing.T) {
	logf.SetLogger(logr.Discard())
	g := NewWithT(t)

	// Capturing upstream: records the inbound Authorization header (the FAT)
	// and the presence/absence of Range, X-Api-Token, and a custom
	// X-Vector-Store-Id header.
	var fatHeader, rangeHeader, apiTokenHeader, vectorStoreHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fatHeader = r.Header.Get("Authorization")
		rangeHeader = r.Header.Get("Range")
		apiTokenHeader = r.Header.Get("X-Api-Token")
		vectorStoreHeader = r.Header.Get("X-Vector-Store-Id")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("FILEBYTES"))
	}))
	t.Cleanup(upstream.Close)

	ttl := time.Minute
	cacheManager, err := cache.NewCacheManager("", "url-delivery-real-proxy-test", &ttl)
	g.Expect(err).ToNot(HaveOccurred())

	hh := &HostHandler{
		log:          logr.Discard(),
		authConfig:   testURLAuthConfig(t), // real ECDSA ActivePair + Audience/Issuer + MintTokenURLDelivery
		cacheManager: cacheManager,
		authChecker:  auth.NewAuthorizationChecker(nil, logr.Discard()),
	}

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-files", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			API: kdexv1alpha1.API{BasePath: "/api/v1/files"},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{URL: upstream.URL},
	}

	handler := hh.reverseProxyHandler(fn, hh.authConfig.Issuer)
	mux := http.NewServeMux()
	mux.Handle("/api/v1/files", handler)
	mux.Handle("/api/v1/files/", handler)
	hh.Mux = mux
	hh.transferHandler(mux, map[string]ko.PathInfo{})

	held := []string{"functions:/api/v1/files:read"}
	res, err := hh.mintCapabilityToken(context.Background(), "alice", held,
		MintTokenRequest{
			Entitlements: held,
			Delivery:     "url",
			Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
		}, "https://dev.example")
	g.Expect(err).ToNot(HaveOccurred())
	path := strings.TrimPrefix(res.URL, "https://dev.example")

	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer recipient-token")
	req.Header.Set("X-Api-Token", "recipient-key")
	req.Header.Set("X-Vector-Store-Id", "evil")
	req.Header.Set("Range", "bytes=0-10")

	rw := httptest.NewRecorder()
	mux.ServeHTTP(rw, req)

	g.Expect(rw.Code).To(Equal(http.StatusOK), "identity gate must have admitted the request and reached upstream")
	g.Expect(rw.Body.String()).To(Equal("FILEBYTES"))

	// The FAT reaching upstream is a non-empty, distinct Bearer credential —
	// the minted Function Access Token, never the recipient's own header.
	g.Expect(fatHeader).ToNot(BeEmpty())
	g.Expect(fatHeader).To(HavePrefix("Bearer "))
	g.Expect(fatHeader).ToNot(Equal("Bearer recipient-token"))

	// Confirm it's genuinely the minted FAT: parses and verifies against the
	// host's own public key, with the expected audience/issuer.
	var claims jwt.MapClaims
	_, verr := jwt.ParseWithClaims(strings.TrimPrefix(fatHeader, "Bearer "), &claims, func(*jwt.Token) (any, error) {
		return hh.authConfig.ActivePair.Private.Public(), nil
	}, jwt.WithAudience(fatAudienceFor(fn)), jwt.WithIssuer(hh.authConfig.Issuer))
	g.Expect(verr).ToNot(HaveOccurred())
	g.Expect(claims["sub"]).To(Equal("alice"))

	// Range is download-safe and allowlisted — it reaches the backend.
	g.Expect(rangeHeader).To(Equal("bytes=0-10"))

	// X-Api-Token (recipient credential) and the arbitrary X-Vector-Store-Id
	// header are NOT allowlisted — FIX #1 strips them before re-dispatch, so
	// they never reach the backend.
	g.Expect(apiTokenHeader).To(BeEmpty())
	g.Expect(vectorStoreHeader).To(BeEmpty())
}
