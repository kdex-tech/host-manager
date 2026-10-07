package host

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func catalogFixture(t *testing.T) *http.ServeMux {
	t.Helper()
	hh := &HostHandler{
		log:         logr.Discard(),
		scheme:      "https",
		authChecker: auth.NewAuthorizationChecker(nil, logr.Discard()),
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{"catalog.example"}},
		},
		registeredPaths: map[string]ko.PathInfo{
			// A page contributes the implicit identity requirement pages/read.
			"/docs": {Type: ko.PagePathType, API: ko.OpenAPI{BasePath: "/docs"}},
			// A function contributes functions/read (its implicit identity),
			// every security entry, and every x-kdex-entitlements entry.
			"/api/v1/roles/{key}": {
				Type: ko.FunctionPathType,
				API: ko.OpenAPI{
					BasePath: "/api/v1/roles",
					Paths: map[string]ko.PathItem{
						"/api/v1/roles/{key}": {
							Put: &openapi.Operation{
								Security: &openapi.SecurityRequirements{
									{"bearer": {"roles:{key}:assign", "roles_create"}},
									{"apiKeyHeader": {"roles:{key}:assign"}},
								},
								Extensions: map[string]any{
									"x-kdex-entitlements": []any{"users:{id}:update_roles", "a:b:c:d"},
								},
							},
						},
					},
				},
			},
			// A host system path contributes its declared security.
			"/-/apitokens/mint": {
				Type: ko.SystemPathType,
				API: ko.OpenAPI{
					Paths: map[string]ko.PathItem{
						"/-/apitokens/mint": {
							Post: &openapi.Operation{
								Security: &openapi.SecurityRequirements{{"bearer": {"apitokens:mint"}}},
							},
						},
					},
				},
			},
		},
	}
	mux := http.NewServeMux()
	paths := map[string]ko.PathInfo{}
	hh.entitlementCatalogHandler(mux, paths)
	assert.Contains(t, paths, entitlementCatalogPath, "the catalog must appear in /-/openapi")
	return mux
}

type catalogVerb struct {
	Verb  string   `json:"verb"`
	All   *bool    `json:"all,omitempty"`
	Names []string `json:"names,omitempty"`
}

type catalogBody struct {
	Resources []struct {
		Resource string        `json:"resource"`
		Verbs    []catalogVerb `json:"verbs"`
	} `json:"resources"`
	Scopes []string `json:"scopes"`
}

func getCatalog(t *testing.T, mux *http.ServeMux, query string, held []string) (int, catalogBody) {
	t.Helper()
	req := httptest.NewRequest("GET", entitlementCatalogPath+query, nil)
	if held != nil {
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "tester", "entitlements": held}))
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	var body catalogBody
	if rr.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
		assert.Contains(t, rr.Header().Get("Cache-Control"), "private")
	}
	return rr.Code, body
}

func flatten(b catalogBody) map[string]catalogVerb {
	out := map[string]catalogVerb{}
	for _, r := range b.Resources {
		for _, v := range r.Verbs {
			out[r.Resource+"/"+v.Verb] = v
		}
	}
	return out
}

// ?all=true is the unclamped catalog: every (resource, verb) and every scope
// the site declares it checks. Names -- placeholders included -- are not part
// of it, and a malformed declaration is skipped, not reported as a scope.
func TestEntitlementCatalog_Unclamped(t *testing.T) {
	code, body := getCatalog(t, catalogFixture(t), "?all=true", nil)
	require.Equal(t, http.StatusOK, code, "the unclamped catalog says no more than /-/openapi, which is public")

	got := map[string]bool{}
	for k, v := range flatten(body) {
		got[k] = true
		assert.Nil(t, v.All, "%s: no clamp fields when unclamped", k)
		assert.Empty(t, v.Names, "%s", k)
	}
	assert.Equal(t, map[string]bool{
		"apitokens/mint":     true,
		"functions/read":     true,
		"pages/read":         true,
		"roles/assign":       true,
		"users/update_roles": true,
	}, got)
	assert.Equal(t, []string{"roles_create"}, body.Scopes)

	var order []string
	for _, r := range body.Resources {
		order = append(order, r.Resource)
	}
	assert.Equal(t, []string{"apitokens", "functions", "pages", "roles", "users"}, order, "resources are sorted")
}

// The default catalog is clamped to what the caller holds (the token's
// entitlements, the set mint_token attenuates against): a pair appears only
// when some held entitlement dominates it for some name; "all" when one
// dominates it for every name; otherwise the specific names held.
func TestEntitlementCatalog_ClampedToCaller(t *testing.T) {
	held := []string{
		"roles:analysts:assign",
		"roles:engineers:all", // verb "all" dominates assign
		"pages::read",
		"functions:/api/v1/roles:read",
		"users:*:update_roles",
		"roles_create",
		"unrelated_scope",
	}
	code, body := getCatalog(t, catalogFixture(t), "", held)
	require.Equal(t, http.StatusOK, code)

	got := flatten(body)
	assert.Equal(t, map[string]catalogVerb{
		"roles/assign":       {Verb: "assign", All: new(false), Names: []string{"analysts", "engineers"}},
		"pages/read":         {Verb: "read", All: new(true)},
		"functions/read":     {Verb: "read", All: new(false), Names: []string{"/api/v1/roles"}},
		"users/update_roles": {Verb: "update_roles", All: new(true)},
	}, got, "apitokens/mint is not held, so it is absent")
	assert.Equal(t, []string{"roles_create"}, body.Scopes, "only declared scopes the caller holds exactly")
}

func TestEntitlementCatalog_ClampedNeedsACaller(t *testing.T) {
	code, _ := getCatalog(t, catalogFixture(t), "", nil)
	assert.Equal(t, http.StatusUnauthorized, code)
}
