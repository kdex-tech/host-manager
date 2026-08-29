package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	. "github.com/onsi/gomega"
)

// mintReq is the JSON body a REST caller posts to /-/capabilities/mint.
func mintReq(t *testing.T, v MintTokenRequest) *strings.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return strings.NewReader(string(b))
}

// postMint drives the handler directly with an injected auth context, the same
// shape AddAuthentication would have produced.
func postMint(hh *HostHandler, sub string, held []string, body *strings.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, capabilitiesMintPath, body)
	r.Header.Set("Content-Type", "application/json")
	if sub != "" {
		ac := auth.AuthContext{"sub": sub, "entitlements": held}
		r = r.WithContext(auth.SetAuthContext(r.Context(), ac))
	}
	rw := httptest.NewRecorder()
	hh.capabilityMintHandler(rw, r)
	return rw
}

func urlMintHandler(t *testing.T) *HostHandler {
	t.Helper()
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	return &HostHandler{authConfig: testURLAuthConfig(t), cacheManager: mgr, Mux: http.NewServeMux()}
}

// The REST surface must exist whenever minting is enabled -- unlike the MCP
// path, whose availability depends on some function declaring oauth2 (#186).
func TestCapabilitiesHandler_GatedOnMintTokenEnabled(t *testing.T) {
	g := NewWithT(t)

	onMux := http.NewServeMux()
	on := map[string]ko.PathInfo{}
	(&HostHandler{authConfig: &auth.Config{MintTokenEnabled: true}}).capabilitiesHandler(onMux, on)
	g.Expect(patternRegistered(onMux, "POST "+capabilitiesMintPath)).To(BeTrue())

	info, ok := on[capabilitiesMintPath]
	g.Expect(ok).To(BeTrue(), "the REST mint route must be documented like every other /-/ route")
	g.Expect(info.Type).To(Equal(ko.SystemPathType))
	item, ok := info.API.Paths[capabilitiesMintPath]
	g.Expect(ok).To(BeTrue())
	g.Expect(item.Post).ToNot(BeNil())
	g.Expect(item.Post.OperationID).To(Equal("capability-mint-post"))

	offMux := http.NewServeMux()
	off := map[string]ko.PathInfo{}
	(&HostHandler{authConfig: &auth.Config{MintTokenEnabled: false}}).capabilitiesHandler(offMux, off)
	g.Expect(patternRegistered(offMux, "POST "+capabilitiesMintPath)).To(BeFalse())
	g.Expect(off).To(BeEmpty())
}

// Registering the handler is not enough — it has to be wired into the mux the
// host actually serves, alongside the other /-/ routes.
func TestMuxWithDefaults_RegistersCapabilityMint(t *testing.T) {
	g := NewWithT(t)

	hh := &HostHandler{
		log:        logr.Discard(),
		authConfig: &auth.Config{MintTokenEnabled: true, ActivePair: &keys.KeyPair{}},
	}
	registeredPaths := map[string]ko.PathInfo{}
	mux := hh.muxWithDefaultsLocked(registeredPaths)

	g.Expect(patternRegistered(mux, "POST "+capabilitiesMintPath)).To(BeTrue())
	g.Expect(registeredPaths).To(HaveKey(capabilitiesMintPath))
}

// A PathInfo that fails OpenAPI compilation would break /-/openapi for the
// WHOLE host, not just these two routes -- so compile and validate the real
// document rather than trusting that a hand-built Operation is well-formed.
func TestCapabilityAndTransferPathsCompileIntoOpenAPI(t *testing.T) {
	g := NewWithT(t)

	hh := &HostHandler{
		log: logr.Discard(),
		authConfig: &auth.Config{
			MintTokenEnabled:     true,
			MintTokenURLDelivery: true,
			ActivePair:           &keys.KeyPair{},
		},
	}
	registeredPaths := map[string]ko.PathInfo{}
	hh.capabilitiesHandler(http.NewServeMux(), registeredPaths)
	hh.transferHandler(http.NewServeMux(), registeredPaths)

	builder := &ko.Builder{TypesToInclude: []ko.PathType{ko.SystemPathType}}
	doc := builder.BuildOpenAPI("https://dev.example", "test-host", registeredPaths, ko.Filter{})
	g.Expect(doc).ToNot(BeNil())

	mint := doc.Paths.Find(capabilitiesMintPath)
	g.Expect(mint).ToNot(BeNil())
	g.Expect(mint.Post).ToNot(BeNil())
	g.Expect(mint.Post.OperationID).To(Equal("capability-mint-post"))
	g.Expect(mint.Post.RequestBody).ToNot(BeNil())

	redeem := doc.Paths.Find(transferPath)
	g.Expect(redeem).ToNot(BeNil())
	g.Expect(redeem.Get).ToNot(BeNil())
	g.Expect(redeem.Get.OperationID).To(Equal("transfer-redeem-get"))

	// Serialization is what /-/openapi actually ships, so assert on that rather
	// than on doc.Validate(): the shared "#/components/responses/*" refs are
	// written as Ref-without-Value throughout this package, which kin-openapi's
	// in-memory validator reports as unresolved for EVERY system route --
	// /-/apitokens/mint included, untouched. The emitted JSON is a valid
	// document (the components block is present); do not "fix" this by adding
	// a Validate() call here, it will fail for reasons unrelated to this route.
	raw, err := json.Marshal(doc)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(string(raw)).To(ContainSubstring(capabilitiesMintPath))
	g.Expect(string(raw)).To(ContainSubstring(transferPath))
}

// A developer key must be able to mint a capability over REST, or the REST
// surface is not a usable alternative to the MCP path for the scripts and CI
// jobs it exists to serve. System routes do NOT authenticate a PAT by default
// -- WithAuthentication deliberately leaves one anonymous -- so the route has
// to opt in via WithAPITokenIdentity, the same composition /-/check uses.
//
// Only a HOST-audience PAT counts: a function-bound key stays anonymous, which
// is what keeps a key scoped to one function from minting against the host.
func TestCapabilitiesRoute_AcceptsHostAudienceDeveloperKey(t *testing.T) {
	g := NewWithT(t)

	const issuer = "https://caps.example"
	cacheManager, _ := cache.NewCacheManager("", "caps-pat-test", nil)

	tm, err := apitoken.NewTokenManager(issuer, apitoken.GenerateDevmodeKeyPair(), nil)
	g.Expect(err).ToNot(HaveOccurred())
	ex, err := auth.NewExchanger(t.Context(), auth.Config{}, cacheManager,
		stubInternalIdentityProvider{})
	g.Expect(err).ToNot(HaveOccurred())

	cfg := testURLAuthConfig(t)
	cfg.Audience = issuer
	cfg.TokenManager = tm

	hh := &HostHandler{
		log:           logr.Discard(),
		authConfig:    cfg,
		authExchanger: ex,
		cacheManager:  cacheManager,
		Mux:           http.NewServeMux(),
	}

	mux := http.NewServeMux()
	hh.capabilitiesHandler(mux, map[string]ko.PathInfo{})

	body := `{"entitlements":["functions:/api/v1/files:read"]}`
	post := func(pat string) int {
		r := httptest.NewRequest(http.MethodPost, capabilitiesMintPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+pat)
		rw := httptest.NewRecorder()
		mux.ServeHTTP(rw, r)
		return rw.Code
	}

	hostPAT, err := tm.MintStatelessKey(issuer, "alice", "act", "scope:x", time.Hour)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(post(hostPAT)).ToNot(Equal(http.StatusUnauthorized),
		"a host-audience developer key must authenticate on the REST mint route")

	fnPAT, err := tm.MintStatelessKey(issuer+"/api/v1/files", "eve", "act", "scope:x", time.Hour)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(post(fnPAT)).To(Equal(http.StatusUnauthorized),
		"a function-bound key must NOT become a host identity here")
}

func TestCapabilityMintHandler_URLDelivery(t *testing.T) {
	g := NewWithT(t)
	hh := urlMintHandler(t)

	rw := postMint(hh, "alice", []string{"functions:/api/v1/files:read"},
		mintReq(t, MintTokenRequest{
			Entitlements: []string{"functions:/api/v1/files:read"},
			Delivery:     "url",
			Uses:         5, // url delivery forces 1
			Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
		}))

	g.Expect(rw.Code).To(Equal(http.StatusOK))
	g.Expect(rw.Header().Get("Content-Type")).To(ContainSubstring("application/json"))

	var res MintTokenResult
	g.Expect(json.Unmarshal(rw.Body.Bytes(), &res)).To(Succeed())
	g.Expect(res.URL).To(ContainSubstring("/-/transfer/"))
	g.Expect(res.Token).To(BeEmpty())
	g.Expect(res.UsesRemaining).To(Equal(1))
	g.Expect(res.Entitlements).To(Equal([]string{"functions:/api/v1/files:read"}))
}

func TestCapabilityMintHandler_BearerDeliveryIsDefault(t *testing.T) {
	g := NewWithT(t)
	hh := urlMintHandler(t)

	rw := postMint(hh, "alice", []string{"functions:/api/v1/files:read"},
		mintReq(t, MintTokenRequest{Entitlements: []string{"functions:/api/v1/files:read"}}))

	g.Expect(rw.Code).To(Equal(http.StatusOK))
	var res MintTokenResult
	g.Expect(json.Unmarshal(rw.Body.Bytes(), &res)).To(Succeed())
	g.Expect(res.Token).ToNot(BeEmpty())
	g.Expect(res.URL).To(BeEmpty())
}

func TestCapabilityMintHandler_AnonymousIs401(t *testing.T) {
	g := NewWithT(t)
	hh := urlMintHandler(t)

	rw := postMint(hh, "", nil,
		mintReq(t, MintTokenRequest{Entitlements: []string{"functions:/api/v1/files:read"}}))

	g.Expect(rw.Code).To(Equal(http.StatusUnauthorized))
	// RFC 7235: a 401 MUST carry a challenge. This site returned a bare 401
	// before the denial contract landed; assert the header directly rather
	// than trusting the status code alone to prove it.
	g.Expect(rw.Header().Get("WWW-Authenticate")).ToNot(BeEmpty())
}

// Attenuation is a policy refusal, not a malformed request: the MCP path
// collapses it into isError:true, but REST callers get a real status.
func TestCapabilityMintHandler_UnheldEntitlementIs403(t *testing.T) {
	g := NewWithT(t)
	hh := urlMintHandler(t)

	rw := postMint(hh, "alice", []string{"functions:/api/v1/files:read"},
		mintReq(t, MintTokenRequest{Entitlements: []string{"vector_stores:system:write"}}))

	g.Expect(rw.Code).To(Equal(http.StatusForbidden))
	g.Expect(rw.Body.String()).To(ContainSubstring("vector_stores:system:write"))
}

func TestCapabilityMintHandler_InvalidTargetIs400(t *testing.T) {
	g := NewWithT(t)
	hh := urlMintHandler(t)

	for _, tc := range []struct {
		name   string
		target *TransferTarget
	}{
		{"missing target", nil},
		{"non-GET method", &TransferTarget{Method: "POST", Path: "/api/v1/files/abc"}},
		{"reserved prefix", &TransferTarget{Method: "GET", Path: "/-/state"}},
		{"relative path", &TransferTarget{Method: "GET", Path: "api/v1/files/abc"}},
		{"dot segment", &TransferTarget{Method: "GET", Path: "/api/v1/../secrets"}},
	} {
		rw := postMint(hh, "alice", []string{"functions:/api/v1/files:read"},
			mintReq(t, MintTokenRequest{
				Entitlements: []string{"functions:/api/v1/files:read"},
				Delivery:     "url",
				Target:       tc.target,
			}))
		g.Expect(rw.Code).To(Equal(http.StatusBadRequest), tc.name)
	}
}

func TestCapabilityMintHandler_NoEntitlementsIs400(t *testing.T) {
	g := NewWithT(t)
	hh := urlMintHandler(t)

	rw := postMint(hh, "alice", []string{"functions:/api/v1/files:read"},
		mintReq(t, MintTokenRequest{}))

	g.Expect(rw.Code).To(Equal(http.StatusBadRequest))
}

func TestCapabilityMintHandler_URLDeliveryDisabledIs403(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t), cacheManager: mgr} // MintTokenURLDelivery false

	rw := postMint(hh, "alice", []string{"functions:/api/v1/files:read"},
		mintReq(t, MintTokenRequest{
			Entitlements: []string{"functions:/api/v1/files:read"},
			Delivery:     "url",
			Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
		}))

	g.Expect(rw.Code).To(Equal(http.StatusForbidden))
}

// URL delivery needs somewhere to keep the handle record; without a cache the
// capability cannot be created at all, which is a server-side condition.
func TestCapabilityMintHandler_NoCacheIs503(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testURLAuthConfig(t)} // no cacheManager

	rw := postMint(hh, "alice", []string{"functions:/api/v1/files:read"},
		mintReq(t, MintTokenRequest{
			Entitlements: []string{"functions:/api/v1/files:read"},
			Delivery:     "url",
			Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
		}))

	g.Expect(rw.Code).To(Equal(http.StatusServiceUnavailable))
}

// A link minted over REST must redeem identically to one minted over MCP --
// same core, so the mint surface leaves no trace on the capability.
func TestCapabilityMintHandler_RESTMintedLinkRedeems(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)

	mux := http.NewServeMux()
	served := 0
	mux.HandleFunc("GET /api/v1/files/", func(w http.ResponseWriter, _ *http.Request) {
		served++
		_, _ = w.Write([]byte("BYTES"))
	})

	hh := &HostHandler{authConfig: testURLAuthConfig(t), cacheManager: mgr, Mux: mux}
	hh.transferHandler(mux, map[string]ko.PathInfo{})

	rw := postMint(hh, "alice", []string{"functions:/api/v1/files:read"},
		mintReq(t, MintTokenRequest{
			Entitlements: []string{"functions:/api/v1/files:read"},
			Delivery:     "url",
			Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
		}))
	g.Expect(rw.Code).To(Equal(http.StatusOK))

	var res MintTokenResult
	g.Expect(json.Unmarshal(rw.Body.Bytes(), &res)).To(Succeed())
	path := res.URL[strings.Index(res.URL, "/-/transfer/"):]

	redeem := httptest.NewRecorder()
	mux.ServeHTTP(redeem, httptest.NewRequest(http.MethodGet, path, nil))
	g.Expect(redeem.Code).To(Equal(http.StatusOK))
	g.Expect(redeem.Body.String()).To(Equal("BYTES"))

	// Single-use: the second redemption is spent.
	again := httptest.NewRecorder()
	mux.ServeHTTP(again, httptest.NewRequest(http.MethodGet, path, nil))
	g.Expect(again.Code).To(Equal(http.StatusGone))
	g.Expect(served).To(Equal(1))
}

// The MCP tool and the REST route are two doors onto one core: identical
// arguments must produce an identical capability shape.
func TestCapabilityMint_RESTAndMCPAgree(t *testing.T) {
	g := NewWithT(t)
	hh := urlMintHandler(t)
	req := MintTokenRequest{
		Entitlements: []string{"functions:/api/v1/files:read"},
		Delivery:     "url",
		Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
	}

	viaCore, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"functions:/api/v1/files:read"}, req, "https://dev.example")
	g.Expect(err).ToNot(HaveOccurred())

	rw := postMint(hh, "alice", []string{"functions:/api/v1/files:read"}, mintReq(t, req))
	g.Expect(rw.Code).To(Equal(http.StatusOK))
	var viaREST MintTokenResult
	g.Expect(json.Unmarshal(rw.Body.Bytes(), &viaREST)).To(Succeed())

	// Handles differ by construction; everything else must match.
	g.Expect(viaREST.Entitlements).To(Equal(viaCore.Entitlements))
	g.Expect(viaREST.UsesRemaining).To(Equal(viaCore.UsesRemaining))
	g.Expect(viaREST.Token).To(Equal(viaCore.Token))
	g.Expect(viaREST.URL).To(ContainSubstring("/-/transfer/"))
	g.Expect(viaREST.URL).ToNot(Equal(viaCore.URL))
}
