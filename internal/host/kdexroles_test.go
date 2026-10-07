package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// roleListingProvider is an identity provider that can list roles, standing in
// for the cluster-backed scopeProvider.
type roleListingProvider struct{ roles []auth.RoleInfo }

func (roleListingProvider) FindInternal(string, string) (jwt.MapClaims, error) { return nil, nil }
func (roleListingProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}
func (p roleListingProvider) Roles() []auth.RoleInfo { return p.roles }

var testRoles = []auth.RoleInfo{
	{
		Name:         "admin",
		Rules:        []kdexv1alpha1.PolicyRule{{Scopes: []string{"roles_create"}}},
		Entitlements: []string{"roles_create"},
	},
	{
		Name:         "viewer",
		Rules:        []kdexv1alpha1.PolicyRule{{Resources: []string{"pages"}, Verbs: []string{"read"}}},
		Entitlements: []string{"pages::read"},
	},
}

func kdexRolesMux(t *testing.T) *http.ServeMux {
	t.Helper()
	ex, err := auth.NewExchanger(context.Background(), auth.Config{}, nil, roleListingProvider{roles: testRoles}, nil)
	require.NoError(t, err)
	hh := &HostHandler{
		log:           logr.Discard(),
		scheme:        "https",
		authChecker:   auth.NewAuthorizationChecker(nil, logr.Discard()),
		authExchanger: ex,
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{"roles.example"}},
		},
	}
	mux := http.NewServeMux()
	paths := map[string]ko.PathInfo{}
	hh.kdexRolesHandler(mux, paths)
	assert.Contains(t, paths, "/-/roles", "the list must be registered so it appears in /-/openapi")
	assert.Contains(t, paths, "/-/roles/{name}")
	return mux
}

// held == nil means no auth context at all (anonymous).
func getRoles(t *testing.T, mux *http.ServeMux, path string, held []string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if held != nil {
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "tester", "entitlements": held}))
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func roleNames(t *testing.T, rr *httptest.ResponseRecorder) []string {
	t.Helper()
	var body struct {
		Items []auth.RoleInfo `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
	names := []string{}
	for _, r := range body.Items {
		names = append(names, r.Name)
	}
	return names
}

// GET /-/roles lists only the roles the caller may read: a per-role grant
// kdexroles:<name>:read shows that role, the wildcard shows them all (#231).
func TestKDexRoles_ListIsFilteredPerRole(t *testing.T) {
	mux := kdexRolesMux(t)

	rr := getRoles(t, mux, "/-/roles", []string{"kdexroles:viewer:read"})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"viewer"}, roleNames(t, rr))
	assert.Contains(t, rr.Header().Get("Cache-Control"), "private")

	rr = getRoles(t, mux, "/-/roles", []string{"kdexroles::read"})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"admin", "viewer"}, roleNames(t, rr))

	var body struct {
		Items []auth.RoleInfo `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, testRoles, body.Items, "rules and compiled entitlements are returned as-is")

	rr = getRoles(t, mux, "/-/roles", []string{"pages::read"})
	require.Equal(t, http.StatusOK, rr.Code, "an authenticated caller who may read no role gets an empty list")
	assert.Empty(t, roleNames(t, rr))
}

func TestKDexRoles_AnonymousListIsChallenged(t *testing.T) {
	rr := getRoles(t, kdexRolesMux(t), "/-/roles", nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("WWW-Authenticate"))
}

// GET /-/roles/{name} decides authorization BEFORE existence, so a denial never
// tells a caller which role names exist.
func TestKDexRoles_GetByName(t *testing.T) {
	mux := kdexRolesMux(t)

	rr := getRoles(t, mux, "/-/roles/viewer", []string{"kdexroles:viewer:read"})
	require.Equal(t, http.StatusOK, rr.Code)
	var got auth.RoleInfo
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, testRoles[1], got)

	assert.Equal(t, http.StatusForbidden, getRoles(t, mux, "/-/roles/admin", []string{"kdexroles:viewer:read"}).Code)
	assert.Equal(t, http.StatusForbidden, getRoles(t, mux, "/-/roles/missing", []string{"kdexroles:viewer:read"}).Code,
		"a missing role is denied exactly like an existing one the caller may not read")
	assert.Equal(t, http.StatusNotFound, getRoles(t, mux, "/-/roles/missing", []string{"kdexroles::read"}).Code)
	assert.Equal(t, http.StatusUnauthorized, getRoles(t, mux, "/-/roles/viewer", nil).Code)
}

// With auth disabled (no checker) there is nothing to gate the listing on, so
// the endpoints are not registered at all.
func TestKDexRoles_NotRegisteredWithoutAuth(t *testing.T) {
	hh := &HostHandler{log: logr.Discard()}
	mux := http.NewServeMux()
	paths := map[string]ko.PathInfo{}
	hh.kdexRolesHandler(mux, paths)
	assert.Empty(t, paths)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/-/roles", nil))
	assert.Equal(t, http.StatusNotFound, rr.Code)
}
