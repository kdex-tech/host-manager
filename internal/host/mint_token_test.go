package host

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/intstr"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func testAuthConfigForMint(t *testing.T) *auth.Config {
	t.Helper()
	kp := keys.GenerateECDSAKeyPair() // ECDSA P-256 dev pair
	return &auth.Config{
		Audience:                  "https://dev.example",
		Issuer:                    "https://dev.example",
		ActivePair:                kp.ActiveKey(),
		MintTokenEnabled:          true,
		MintTokenTTLCap:           60 * time.Second,
		MintTokenUsesCap:          32,
		MintTokenDestructiveVerbs: []string{"delete", "own"},
	}
}

func TestMintCapabilityToken_AttenuatesAndSignsHostAudience(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	held := []string{"functions:/api/v1/files:write", "functions:/api/v1/files:read"}

	res, err := hh.mintCapabilityToken(context.Background(), "alice", held, MintTokenRequest{
		Entitlements: []string{"functions:/api/v1/files:write"},
		TTLSeconds:   30,
	}, "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Entitlements).To(Equal([]string{"functions:/api/v1/files:write"}))

	// Parse back with the active public key; assert host audience + claim.
	var claims jwt.MapClaims
	_, perr := jwt.ParseWithClaims(res.Token, &claims, func(*jwt.Token) (any, error) {
		return hh.authConfig.ActivePair.Private.Public(), nil
	}, jwt.WithAudience("https://dev.example"), jwt.WithIssuer("https://dev.example"))
	g.Expect(perr).ToNot(HaveOccurred())
	g.Expect(claims["sub"]).To(Equal("alice"))
	g.Expect(claims["entitlements"]).To(ContainElement("functions:/api/v1/files:write"))
	g.Expect(claims[auth.CapUsesClaim]).To(BeTrue())
}

func TestMintCapabilityToken_RejectsOverBroad(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	held := []string{"functions:/api/v1/files:write"}

	_, err := hh.mintCapabilityToken(context.Background(), "alice", held, MintTokenRequest{
		Entitlements: []string{"functions:/api/v1/files:*"},
	}, "")
	g.Expect(err).To(MatchError(ContainSubstring("functions:/api/v1/files:*")))
}

func TestMintCapabilityToken_ClampsTTL(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"pages:/:read"}, MintTokenRequest{Entitlements: []string{"pages:/:read"}, TTLSeconds: 99999}, "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.ExpiresAt).To(BeNumerically("<=", time.Now().Add(61*time.Second).Unix()))
}

func TestMintCapabilityToken_DestructiveVerbForcing(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}

	// Explicit destructive verb: forced to uses=1 and ttl<=10s even though
	// the caller asked for uses=5 and a 60s ttl.
	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"vector_stores:X:delete"},
		MintTokenRequest{Entitlements: []string{"vector_stores:X:delete"}, Uses: 5, TTLSeconds: 60}, "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.UsesRemaining).To(Equal(1))
	g.Expect(res.ExpiresAt).To(BeNumerically("<=", time.Now().Add(11*time.Second).Unix()))

	// Wildcard verb encompasses destructive verbs -> same forcing.
	res2, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"vector_stores:X:all"},
		MintTokenRequest{Entitlements: []string{"vector_stores:X:all"}, Uses: 5, TTLSeconds: 60}, "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res2.UsesRemaining).To(Equal(1))
	g.Expect(res2.ExpiresAt).To(BeNumerically("<=", time.Now().Add(11*time.Second).Unix()))
}

func TestMintCapabilityToken_ProvisionsCounter(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t), cacheManager: mgr}

	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"functions:/api/v1/files:write"},
		MintTokenRequest{Entitlements: []string{"functions:/api/v1/files:write"}, Uses: 3}, "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.UsesRemaining).To(Equal(3))

	// Extract jti and confirm the counter exists with value "3".
	var claims jwt.MapClaims
	_, _ = jwt.ParseWithClaims(res.Token, &claims, func(*jwt.Token) (any, error) {
		return hh.authConfig.ActivePair.Private.Public(), nil
	})
	jti := claims["jti"].(string)
	c := mgr.GetCache("cap", cache.CacheOptions{Uncycled: true})
	val, exists, _, _ := c.Get(context.Background(), "uses:"+jti)
	g.Expect(exists).To(BeTrue())
	g.Expect(val).To(Equal("3"))
}

func TestIsMintTokenCall(t *testing.T) {
	g := NewWithT(t)
	body := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"mint_token","arguments":{"entitlements":["pages:/:read"],"ttl_seconds":30}}}`)
	id, args, matched := isMintTokenCall(body)
	g.Expect(matched).To(BeTrue())
	g.Expect(string(id)).To(Equal("7"))
	g.Expect(args.Entitlements).To(Equal([]string{"pages:/:read"}))
	g.Expect(args.TTLSeconds).To(Equal(30))

	_, _, m2 := isMintTokenCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_atoms"}}`))
	g.Expect(m2).To(BeFalse())

	_, _, m3 := isMintTokenCall([]byte(`[{"jsonrpc":"2.0"}]`)) // batch passthrough
	g.Expect(m3).To(BeFalse())
}

func TestSpliceMintTokenDescriptor(t *testing.T) {
	g := NewWithT(t)
	resp := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_atoms"}]}}`)
	out, ok := spliceMintTokenDescriptor(resp, "https://dev.knowdrive.ai/-/openapi")
	g.Expect(ok).To(BeTrue())

	var parsed jsonRPCResponse
	g.Expect(json.Unmarshal(out, &parsed)).To(Succeed())
	result := parsed.Result.(map[string]any)
	tools := result["tools"].([]any)

	byName := map[string]map[string]any{}
	for _, tool := range tools {
		m := tool.(map[string]any)
		byName[m["name"].(string)] = m
	}
	// Assert by NAME, not by count: the splice advertises every AS-provided
	// tool (mint_token, whoami, ...), so a length assertion breaks every time
	// one is added without telling us anything useful.
	g.Expect(byName).To(HaveKey("search_atoms"))
	g.Expect(byName).To(HaveKey("mint_token"))
	g.Expect(byName).To(HaveKey("whoami"))

	// #133: the discovery endpoint (resolved to the caller-facing address) must
	// be surfaced inside the mint_token description so an agent can go
	// mint -> read /-/openapi -> call the right route.
	desc := byName["mint_token"]["description"].(string)
	g.Expect(desc).To(ContainSubstring("https://dev.knowdrive.ai/-/openapi"))
	g.Expect(desc).To(ContainSubstring("Authorization: Bearer"))
}

// TestSpliceMintTokenDescriptor_FallsBackWithoutURL covers the defensive path:
// an empty discovery URL (unknown runtime address) must render today's static
// description with no broken "://"-less URL spliced in (#133 acceptance).
func TestSpliceMintTokenDescriptor_FallsBackWithoutURL(t *testing.T) {
	g := NewWithT(t)
	resp := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	out, ok := spliceMintTokenDescriptor(resp, "")
	g.Expect(ok).To(BeTrue())

	var parsed jsonRPCResponse
	g.Expect(json.Unmarshal(out, &parsed)).To(Succeed())
	tools := parsed.Result.(map[string]any)["tools"].([]any)
	var desc string
	for _, tool := range tools {
		m := tool.(map[string]any)
		if m["name"] == "mint_token" {
			desc = m["description"].(string)
		}
	}
	g.Expect(desc).ToNot(BeEmpty(), "mint_token must still be advertised")
	g.Expect(desc).To(ContainSubstring("attenuated capability token"))
	g.Expect(desc).ToNot(ContainSubstring("/-/openapi"))
}

// TestOpenapiDiscoveryURL pins how the discovery URL is derived from the
// caller-facing (forwarded) request address (#133): the URL must reflect the
// forwarded host/scheme so it works behind the GCE ingress / Traefik hop, not
// the internal :8090 address, and must degrade to "" when the host is unknown.
func TestOpenapiDiscoveryURL(t *testing.T) {
	t.Run("prefers X-Forwarded-Host and X-Forwarded-Proto", func(t *testing.T) {
		g := NewWithT(t)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
		r.Host = "host-manager.default.svc.cluster.local:8090"
		r.Header.Set("X-Forwarded-Host", "dev.knowdrive.ai")
		r.Header.Set("X-Forwarded-Proto", "https")
		g.Expect(openapiDiscoveryURL(r)).To(Equal("https://dev.knowdrive.ai/-/openapi"))
	})

	t.Run("takes the first value of a comma-separated forwarded chain", func(t *testing.T) {
		g := NewWithT(t)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
		r.Host = "internal:8090"
		r.Header.Set("X-Forwarded-Host", "dev.knowdrive.ai, traefik.internal")
		r.Header.Set("X-Forwarded-Proto", "https, http")
		g.Expect(openapiDiscoveryURL(r)).To(Equal("https://dev.knowdrive.ai/-/openapi"))
	})

	t.Run("falls back to r.Host and https when no forwarded headers", func(t *testing.T) {
		g := NewWithT(t)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
		r.Host = "dev.example"
		g.Expect(openapiDiscoveryURL(r)).To(Equal("https://dev.example/-/openapi"))
	})

	t.Run("returns empty when host is unknown", func(t *testing.T) {
		g := NewWithT(t)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
		r.Host = ""
		g.Expect(openapiDiscoveryURL(r)).To(Equal(""))
	})
}

func TestIsToolsListCall(t *testing.T) {
	g := NewWithT(t)
	g.Expect(isToolsListCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))).To(BeTrue())
	g.Expect(isToolsListCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))).To(BeFalse())
}

// mintProxyDomain / mintProxyBasePath mirror the oauth2 e2e fixtures' naming
// (see mcp_oauth2_e2e_test.go / proxy_pat_test.go) but scoped to the
// mint_token interception test so as not to collide with those constants.
const (
	mintProxyDomain   = "dev.example"
	mintProxyIssuer   = "https://" + mintProxyDomain
	mintProxyBasePath = "/api/v1/mcp"
)

// newTestHostHandlerForProxy builds a HostHandler with a real in-memory
// cache.CacheManager, an always-authorized authChecker (the interception
// under test sits AFTER the identity gate in reverseProxyHandler, so the
// gate must pass for a request carrying an authContext — mirrors
// entitlementGateChecker in proxy_pat_test.go, which authorizes whenever the
// request's authContext carries resolved entitlements), and the given
// authConfig (MintTokenEnabled=true from testAuthConfigForMint). Mirrors the
// HostHandler construction in mcp_oauth2_e2e_test.go / proxy_pat_test.go.
func newTestHostHandlerForProxy(t *testing.T, cfg *auth.Config) *HostHandler {
	t.Helper()
	logf.SetLogger(logr.Discard())

	ttl := time.Hour
	cacheManager, err := cache.NewCacheManager("", "mint-proxy-test", &ttl)
	if err != nil {
		t.Fatalf("cache.NewCacheManager: %v", err)
	}

	ex, err := auth.NewExchanger(t.Context(), auth.Config{}, cacheManager, stubInternalIdentityProvider{})
	if err != nil {
		t.Fatalf("auth.NewExchanger: %v", err)
	}

	return &HostHandler{
		log:          logr.Discard(),
		scheme:       "https",
		cacheManager: cacheManager,
		authChecker:  &entitlementGateChecker{},
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{mintProxyDomain}},
		},
		authConfig:    cfg,
		authExchanger: ex,
	}
}

// newServiceBackedMCPFunction returns a Ready, Service-backed KDexFunction
// whose single POST /api/v1/mcp operation declares the built-in oauth2
// scheme (so oauth2ProtectedResources() marks it oauth2-protected) and whose
// Status.URL points at the given stub upstream.
func newServiceBackedMCPFunction(t *testing.T, upstreamURL string) *kdexv1alpha1.KDexFunction {
	t.Helper()
	fn := newReadyFunctionWithOAuth2(t, mintProxyBasePath, []string{"functions:" + mintProxyBasePath + ":read"})
	fn.Spec.Backend = &kdexv1alpha1.FunctionBackend{
		Type: kdexv1alpha1.FunctionBackendTypeService,
		Service: &kdexv1alpha1.ServiceBackend{
			Name: "mint-proxy-upstream",
			Port: intstr.FromInt(80),
			Path: "/",
		},
	}
	fn.Status.URL = upstreamURL
	return &fn
}

// TestReverseProxy_InterceptsMintTokenCall proves the mint_token
// interception is wired into the real reverseProxyHandler request path: a
// tools/call for mint_token on an oauth2-protected, mint-token-enabled MCP
// function is answered locally (never forwarded), while an ordinary POST
// would otherwise reach the stub upstream. See #280.
func TestReverseProxy_InterceptsMintTokenCall(t *testing.T) {
	g := NewWithT(t)

	// Stub upstream that must NEVER be called for a mint_token tools/call.
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	hh := newTestHostHandlerForProxy(t, testAuthConfigForMint(t))
	fn := newServiceBackedMCPFunction(t, upstream.URL)
	// oauth2ProtectedResources() enumerates hh.functions; the function must be
	// registered there for reverseProxyHandler to detect it as oauth2-protected
	// (mirrors patProxyFixture / newE2EHarness).
	hh.functions = []kdexv1alpha1.KDexFunction{*fn}
	handler := hh.reverseProxyHandler(fn, mintProxyIssuer)

	body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mint_token","arguments":{"entitlements":["pages:/:read"]}}}`
	req := httptest.NewRequest(http.MethodPost, mintProxyBasePath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub": "alice", "entitlements": []any{"pages:/:read"},
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	g.Expect(upstreamHit).To(BeFalse())
	g.Expect(rr.Code).To(Equal(http.StatusOK))
	var resp jsonRPCResponse
	g.Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
	g.Expect(resp.Result).ToNot(BeNil())
}

// TestReverseProxy_ToolsList_SplicesDiscoveryURL exercises the full proxy path
// (#133 acceptance #1/#2): a tools/list on a mint-token-enabled host renders a
// mint_token descriptor whose description names the /-/openapi discovery URL,
// resolved to the FORWARDED caller-facing address (dev.knowdrive.ai via https)
// rather than the internal upstream address.
func TestReverseProxy_ToolsList_SplicesDiscoveryURL(t *testing.T) {
	g := NewWithT(t)

	// Upstream returns a normal tools/list result; the proxy must splice
	// mint_token into it on the way back.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"search_atoms"}]}}`))
	}))
	defer upstream.Close()

	hh := newTestHostHandlerForProxy(t, testAuthConfigForMint(t))
	fn := newServiceBackedMCPFunction(t, upstream.URL)
	hh.functions = []kdexv1alpha1.KDexFunction{*fn}
	handler := hh.reverseProxyHandler(fn, mintProxyIssuer)

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`
	req := httptest.NewRequest(http.MethodPost, mintProxyBasePath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// The GCE ingress / Traefik hop presents the external address here.
	req.Header.Set("X-Forwarded-Host", "dev.knowdrive.ai")
	req.Header.Set("X-Forwarded-Proto", "https")
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub": "alice", "entitlements": []any{"pages:/:read"},
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusOK))
	var resp jsonRPCResponse
	g.Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
	tools := resp.Result.(map[string]any)["tools"].([]any)
	// By NAME rather than count: the splice advertises every AS-provided tool
	// (mint_token, whoami, ...), so counting breaks on each addition.

	var mintDesc string
	for _, tl := range tools {
		m := tl.(map[string]any)
		if m["name"] == "mint_token" {
			mintDesc = m["description"].(string)
		}
	}
	g.Expect(mintDesc).To(ContainSubstring("https://dev.knowdrive.ai/-/openapi"))
}

// TestReverseProxy_LargeBodyNotTruncated proves that a POST body larger than
// maxMintPeekBytes to a mint-enabled, oauth2-protected MCP function is
// forwarded to the upstream in full — never truncated — even though it is
// not a mint_token call. The mint_token interceptor only buffers up to
// maxMintPeekBytes+1 bytes to classify the body; anything larger must be
// streamed through uninspected rather than silently cut off. See #280.
func TestReverseProxy_LargeBodyNotTruncated(t *testing.T) {
	g := NewWithT(t)

	// Stub upstream that records the full length of the body it receives.
	var upstreamHit bool
	var upstreamBodyLen int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		b, err := io.ReadAll(r.Body)
		g.Expect(err).ToNot(HaveOccurred())
		upstreamBodyLen = len(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	hh := newTestHostHandlerForProxy(t, testAuthConfigForMint(t))
	fn := newServiceBackedMCPFunction(t, upstream.URL)
	hh.functions = []kdexv1alpha1.KDexFunction{*fn}
	handler := hh.reverseProxyHandler(fn, mintProxyIssuer)

	// Build a >maxMintPeekBytes JSON-RPC body that is NOT a mint_token call.
	const argSize = 2 << 20 // 2 MiB
	prefix := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"bulk_ingest_text","arguments":{"text":"`
	suffix := `"}}}`
	text := strings.Repeat("a", argSize)
	body := prefix + text + suffix
	sentLen := len(body)
	g.Expect(sentLen).To(BeNumerically(">", maxMintPeekBytes))

	req := httptest.NewRequest(http.MethodPost, mintProxyBasePath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub": "alice", "entitlements": []any{"pages:/:read"},
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	g.Expect(upstreamHit).To(BeTrue())
	g.Expect(rr.Code).To(Equal(http.StatusOK))
	g.Expect(upstreamBodyLen).To(Equal(sentLen))
}

func testURLAuthConfig(t *testing.T) *auth.Config {
	c := testAuthConfigForMint(t)
	c.MintTokenURLDelivery = true
	return c
}

func TestMintCapabilityToken_URLDelivery(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{authConfig: testURLAuthConfig(t), cacheManager: mgr}

	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"functions:/api/v1/files:read"},
		MintTokenRequest{
			Entitlements: []string{"functions:/api/v1/files:read"},
			Delivery:     "url",
			Uses:         5, // must be forced to 1
			Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
		},
		"https://dev.example")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Token).To(BeEmpty())
	g.Expect(res.UsesRemaining).To(Equal(1))
	g.Expect(res.URL).To(HavePrefix("https://dev.example/-/transfer/"))

	// The handle resolves to a stored record with the bound target.
	handle := strings.TrimPrefix(res.URL, "https://dev.example/-/transfer/")
	rec, ok := hh.loadTransferRecord(context.Background(), handle)
	g.Expect(ok).To(BeTrue())
	g.Expect(rec.Sub).To(Equal("alice"))
	g.Expect(rec.Target.Path).To(Equal("/api/v1/files/abc/content"))
	g.Expect(rec.Entitlements).To(Equal([]string{"functions:/api/v1/files:read"}))
}

func TestMintCapabilityToken_URLDelivery_Rejections(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	ent := []string{"functions:/api/v1/files:read"}

	// Feature off.
	off := &HostHandler{authConfig: testAuthConfigForMint(t), cacheManager: mgr}
	_, err := off.mintCapabilityToken(context.Background(), "alice", ent,
		MintTokenRequest{Entitlements: ent, Delivery: "url",
			Target: &TransferTarget{Method: "GET", Path: "/api/v1/files/x"}}, "https://dev.example")
	g.Expect(err).To(HaveOccurred())

	on := &HostHandler{authConfig: testURLAuthConfig(t), cacheManager: mgr}
	// Missing target.
	_, err = on.mintCapabilityToken(context.Background(), "alice", ent,
		MintTokenRequest{Entitlements: ent, Delivery: "url"}, "https://dev.example")
	g.Expect(err).To(HaveOccurred())
	// Reserved /-/ target.
	_, err = on.mintCapabilityToken(context.Background(), "alice", ent,
		MintTokenRequest{Entitlements: ent, Delivery: "url",
			Target: &TransferTarget{Method: "GET", Path: "/-/state/"}}, "https://dev.example")
	g.Expect(err).To(HaveOccurred())

	// Over-broad entitlement on the URL path must fail attenuation — a URL can
	// never carry more than the caller holds (regression for the URL branch;
	// TestMintCapabilityToken_RejectsOverBroad only covers the bearer path).
	var overBroad MintTokenResult
	overBroad, err = on.mintCapabilityToken(context.Background(), "alice",
		ent, // held: files:read
		MintTokenRequest{Entitlements: []string{"functions:/api/v1/files:write"}, // requested: not held
			Delivery: "url",
			Target:   &TransferTarget{Method: "GET", Path: "/api/v1/files/x"}}, "https://dev.example")
	g.Expect(err).To(HaveOccurred())
	g.Expect(overBroad.URL).To(BeEmpty())

	// Feature on + valid target but NO cache manager -> errNoCache precondition.
	noCache := &HostHandler{authConfig: testURLAuthConfig(t)} // cacheManager nil
	_, err = noCache.mintCapabilityToken(context.Background(), "alice", ent,
		MintTokenRequest{Entitlements: ent, Delivery: "url",
			Target: &TransferTarget{Method: "GET", Path: "/api/v1/files/x"}}, "https://dev.example")
	g.Expect(err).To(HaveOccurred())
}

func TestValidateTransferTarget(t *testing.T) {
	g := NewWithT(t)

	g.Expect(validateTransferTarget(nil)).To(HaveOccurred())
	g.Expect(validateTransferTarget(&TransferTarget{Method: "POST", Path: "/api/v1/files/x/content"})).To(HaveOccurred())
	g.Expect(validateTransferTarget(&TransferTarget{Method: "GET", Path: "api/v1/files/x"})).To(HaveOccurred())          // relative
	g.Expect(validateTransferTarget(&TransferTarget{Method: "GET", Path: "//evil.example/x"})).To(HaveOccurred())        // scheme-relative
	g.Expect(validateTransferTarget(&TransferTarget{Method: "GET", Path: "/-/transfer/abc"})).To(HaveOccurred())         // reserved
	g.Expect(validateTransferTarget(&TransferTarget{Method: "GET", Path: "/api/v1/files/../secret"})).To(HaveOccurred()) // dot-dot traversal
	g.Expect(validateTransferTarget(&TransferTarget{Method: "get", Path: "/api/v1/files/x/content"})).ToNot(HaveOccurred())
}

func TestMintTokenDescriptor_AdvertisesURLDelivery(t *testing.T) {
	g := NewWithT(t)
	d := mintTokenDescriptor("")
	props := d["inputSchema"].(map[string]any)["properties"].(map[string]any)
	g.Expect(props).To(HaveKey("delivery"))
	g.Expect(props).To(HaveKey("target"))
}
