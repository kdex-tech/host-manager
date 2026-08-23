package host

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
)

// transferKeyPrefix namespaces URL-delivery records in the shared "cap" cache
// class (the same class holding the "uses:<jti>" budget counters).
const transferKeyPrefix = "transfer:"

// transferRecord is the server-side capability a /-/transfer/<handle> URL maps
// back to. Claims-only: the signed JWT is never stored or embedded in the URL —
// the unguessable handle plus this record IS the credential, and downstream
// enforcement re-checks the entitlements.
type transferRecord struct {
	JTI          string         `json:"jti"`
	Sub          string         `json:"sub"`
	Entitlements []string       `json:"entitlements"`
	Target       TransferTarget `json:"target"`
}

// newTransferHandle returns a 256-bit unguessable, URL-safe handle.
func newTransferHandle() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// capCache returns the host's bounded-capability cache (nil when no cache
// manager is configured — envtest/dev without Valkey).
func (hh *HostHandler) capCache() cache.Cache {
	if hh.cacheManager == nil {
		return nil
	}
	return hh.cacheManager.GetCache("cap", cache.CacheOptions{Uncycled: true})
}

// storeTransferRecord persists rec under transfer:<handle> with the given TTL.
func (hh *HostHandler) storeTransferRecord(ctx context.Context, handle string, rec transferRecord, ttl time.Duration) error {
	c := hh.capCache()
	if c == nil {
		return errNoCache
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return c.Set(ctx, transferKeyPrefix+handle, string(b), cache.WithTTL(ttl))
}

// loadTransferRecord reads and decodes the record for handle. ok=false on a
// missing/expired key, a read error, or a decode error (all fail-closed).
func (hh *HostHandler) loadTransferRecord(ctx context.Context, handle string) (transferRecord, bool) {
	c := hh.capCache()
	if c == nil {
		return transferRecord{}, false
	}
	val, exists, _, err := c.Get(ctx, transferKeyPrefix+handle)
	if err != nil || !exists {
		return transferRecord{}, false
	}
	var rec transferRecord
	if json.Unmarshal([]byte(val), &rec) != nil {
		return transferRecord{}, false
	}
	return rec, true
}

// transferBaseURL is the caller-facing scheme://host prefix for a redemption
// URL, derived from the forwarded request address; "" when unknown.
func transferBaseURL(r *http.Request) string {
	host := fwdHost(r)
	if host == "" {
		return ""
	}
	return fwdScheme(r) + "://" + host
}

// errNoCache is returned when URL delivery is requested but no cache manager is
// available to hold the handle record / budget counter.
var errNoCache = fmt.Errorf("mint_token url delivery requires a configured cache")

// transferPath is the redemption route for URL-delivered capabilities.
const transferPath = "/-/transfer/{handle}"

// transferHandler registers the redemption route, but only when URL delivery is
// enabled — a disabled host has no /-/transfer surface at all.
//
// The PathInfo is published under the same guard, so the catalog advertises the
// route exactly when the route exists. Documenting it leaks nothing: the
// credential is the 256-bit handle, not the route template — and without an
// entry, an agent reading /-/openapi (which the mint_token descriptor tells it
// to do) never learns the mechanism exists. See kdex-tech/host-manager#185.
func (hh *HostHandler) transferHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if hh.authConfig == nil || !hh.authConfig.MintTokenURLDelivery {
		return
	}
	mux.HandleFunc("GET "+transferPath, hh.TransferGet)

	hh.registerPath(transferPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: transferPath,
			Paths: map[string]ko.PathItem{
				transferPath: {
					Description: "Redeems a single-use capability URL minted with delivery \"url\".",
					Get: &openapi.Operation{
						Description: "GET to redeem the capability and receive the bound target's response. " +
							"Send NO credentials: the handle is the credential, and an Authorization header is " +
							"rejected by the authentication middleware before redemption is reached. The bound " +
							"method and path are fixed at mint time; any query string is discarded, and all " +
							"headers except Accept, Accept-Encoding, Range, If-Range, If-Modified-Since and " +
							"If-None-Match are dropped before the request is re-dispatched.",
						OperationID: "transfer-redeem-get",
						Parameters: openapi.Parameters{
							&openapi.ParameterRef{
								Value: &openapi.Parameter{
									Name:        "handle",
									In:          "path",
									Required:    true,
									Description: "The unguessable 256-bit handle returned by the mint. This value IS the credential.",
									Schema:      &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
								},
							},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Description: new("The bound target's response, passed through unchanged. " +
									"Content type is whatever the target produced."),
							}),
							openapi.WithStatus(401, &openapi.ResponseRef{
								Ref: "#/components/responses/Unauthorized",
							}),
							openapi.WithStatus(410, &openapi.ResponseRef{
								Value: &openapi.Response{
									Description: new("The link is no longer redeemable. Deliberately indistinguishable " +
										"across every cause — already spent, expired, unknown handle, method mismatch, " +
										"or no cache backing the record — so a caller cannot enumerate handles."),
								},
							}),
						),
						Summary: "Redeem a capability URL",
						Tags:    []string{"system", "transfer", "auth"},
					},
					Summary: "Redeem a capability URL",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

// TransferGet redeems a /-/transfer/<handle> capability: resolve the handle,
// spend one budget unit, inject the stored identity, and re-dispatch the bound
// target through the mux (which runs the proxy identity gate + per-op security
// against the injected entitlements). All non-redeemable cases return an
// identical 410 to preserve anti-enumeration.
func (hh *HostHandler) TransferGet(w http.ResponseWriter, r *http.Request) {
	gone := func() { http.Error(w, "This transfer link is no longer valid.", http.StatusGone) }

	ctx := r.Context()
	rec, ok := hh.loadTransferRecord(ctx, r.PathValue("handle"))
	if !ok {
		gone()
		return
	}
	if !strings.EqualFold(r.Method, rec.Target.Method) {
		gone()
		return
	}
	c := hh.capCache()
	if c == nil {
		gone()
		return
	}
	// Snapshot the mux and confirm we can actually serve BEFORE spending the
	// single use — otherwise a transiently-nil mux would burn an
	// otherwise-valid link and then 410. All non-serve preconditions
	// (record, method, cache, mux) are checked ahead of the decrement.
	hh.mu.RLock()
	mux := hh.Mux
	hh.mu.RUnlock()
	if mux == nil {
		gone()
		return
	}
	if _, ok, err := c.DecrementIfPositive(ctx, "uses:"+rec.JTI); err != nil || !ok {
		gone() // spent / expired / missing counter -> fail-closed
		return
	}

	ac := auth.AuthContext{"sub": rec.Sub, "entitlements": rec.Entitlements}
	r2 := r.Clone(auth.SetAuthContext(ctx, ac))
	r2.Method = rec.Target.Method
	r2.URL.Path = rec.Target.Path
	r2.URL.RawPath = ""
	r2.URL.RawQuery = "" // bound target only — recipient cannot append query params
	r2.RequestURI = ""

	// Strip recipient-controlled headers before re-dispatch — symmetric with the
	// RawQuery clear above. A capability URL pins ONE operation; the recipient
	// must not steer the forwarded request (header-sourced entitlement bindings,
	// FAT ClaimMappings, backend auth) via inbound headers. Keep only a
	// download-safe allowlist.
	allowedHeaders := []string{"Accept", "Accept-Encoding", "Range", "If-Range", "If-Modified-Since", "If-None-Match"}
	clean := make(http.Header, len(allowedHeaders))
	for _, h := range allowedHeaders {
		if vs := r2.Header.Values(h); len(vs) > 0 {
			clean[http.CanonicalHeaderKey(h)] = vs
		}
	}
	r2.Header = clean

	mux.ServeHTTP(w, r2)
}
