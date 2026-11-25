package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
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
func (roleListingProvider) FindInternalRolesAndEntitlements(auth.BindingSubject, *auth.BindingNames) ([]string, []string, error) {
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
	mux, _ := kdexRolesMuxLogged(t)
	return mux
}

// logLines captures what a handler logs.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

func kdexRolesMuxLogged(t *testing.T) (*http.ServeMux, *logLines) {
	t.Helper()
	_, mux, logged := kdexRolesHostLogged(t, "roles-host")
	return mux, logged
}

func kdexRolesHostLogged(t *testing.T, name string) (*HostHandler, *http.ServeMux, *logLines) {
	t.Helper()
	logged := &logLines{}
	log := funcr.New(func(prefix, args string) {
		logged.mu.Lock()
		defer logged.mu.Unlock()
		logged.lines = append(logged.lines, args)
	}, funcr.Options{})
	ex, err := auth.NewExchanger(context.Background(), auth.Config{}, nil, roleListingProvider{roles: testRoles}, nil)
	require.NoError(t, err)
	hh := &HostHandler{
		Name:          name,
		log:           log,
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
	return hh, mux, logged
}

// held == nil means no auth context at all (anonymous).
func getRoles(t *testing.T, mux *http.ServeMux, path string, held []string) *httptest.ResponseRecorder {
	t.Helper()
	return getRolesAs(t, mux, path, "tester", held)
}

// getRolesAs is getRoles as subject sub. The deprecation log is once per
// host per subject, so a test asserting it uses a subject of its own.
func getRolesAs(t *testing.T, mux *http.ServeMux, path, sub string, held []string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if held != nil {
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": sub, "entitlements": held}))
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
// roles:<name>:read shows that role, roles::read shows them all (#231). The
// resource is the kdex-roles contract's, so a KDexRole and an app's custom
// role share one key space (#303).
func TestKDexRoles_ListIsFilteredPerRole(t *testing.T) {
	mux := kdexRolesMux(t)

	rr := getRoles(t, mux, "/-/roles", []string{"roles:viewer:read"})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"viewer"}, roleNames(t, rr))
	assert.Contains(t, rr.Header().Get("Cache-Control"), "private")

	rr = getRoles(t, mux, "/-/roles", []string{"roles::read"})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"admin", "viewer"}, roleNames(t, rr))

	var body struct {
		Items []auth.RoleInfo `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, testRoles, body.Items, "rules and compiled entitlements are returned as-is")

	for _, held := range [][]string{{"pages::read"}, {"roles:viewer:update"}, {"roles_list"}, {"role_assignments_read"}} {
		rr = getRoles(t, mux, "/-/roles", held)
		require.Equal(t, http.StatusOK, rr.Code, "an authenticated caller who may read no role gets an empty list")
		assert.Empty(t, roleNames(t, rr), "%v", held)
	}
}

// For one release the legacy kdexroles:<name>:read still admits, alone or
// beside the new grant (#303).
func TestKDexRoles_LegacyGrantStillAdmits(t *testing.T) {
	mux := kdexRolesMux(t)
	sub := t.Name()

	rr := getRolesAs(t, mux, "/-/roles", sub, []string{"kdexroles:viewer:read"})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"viewer"}, roleNames(t, rr))

	rr = getRolesAs(t, mux, "/-/roles", sub, []string{"kdexroles::read"})
	assert.Equal(t, []string{"admin", "viewer"}, roleNames(t, rr))

	rr = getRolesAs(t, mux, "/-/roles", sub, []string{"roles:viewer:read", "kdexroles:admin:read"})
	assert.Equal(t, []string{"admin", "viewer"}, roleNames(t, rr), "either grant suffices")

	assert.Equal(t, http.StatusOK, getRolesAs(t, mux, "/-/roles/viewer", sub, []string{"kdexroles:viewer:read"}).Code)
	assert.Equal(t, http.StatusForbidden, getRolesAs(t, mux, "/-/roles/admin", sub, []string{"kdexroles:viewer:read"}).Code)
	assert.Equal(t, http.StatusNotFound, getRolesAs(t, mux, "/-/roles/missing", sub, []string{"kdexroles::read"}).Code)
}

// A role admitted only by the legacy grant is logged, once per host per
// caller, so the operator can find and migrate the grant without the log
// growing with traffic. One admitted by roles:<name>:read is not logged. The
// caller is logged as a short hash, never its raw subject (#303 quad).
func TestKDexRoles_LegacyGrantLoggedOncePerCaller(t *testing.T) {
	const msg = "deprecated kdexroles entitlement used"
	mux, logged := kdexRolesMuxLogged(t)
	sub := t.Name()

	getRolesAs(t, mux, "/-/roles", sub+"-new", []string{"roles::read"})
	getRolesAs(t, mux, "/-/roles/viewer", sub+"-new", []string{"roles:viewer:read"})
	getRolesAs(t, mux, "/-/roles", sub+"-both", []string{"roles::read", "kdexroles::read"})
	getRolesAs(t, mux, "/-/roles", sub+"-none", []string{"pages::read"})
	assert.Zero(t, logged.count(msg), "the new grant admitted every role: nothing to log")

	for range 3 {
		getRolesAs(t, mux, "/-/roles", sub, []string{"kdexroles::read"})
		getRolesAs(t, mux, "/-/roles/viewer", sub, []string{"kdexroles:viewer:read"})
	}
	assert.Equal(t, 1, logged.count(msg), "once per caller, not per request or per role")
	assert.Equal(t, 1, logged.count("roles:<name>:read"), "the line names the grant to migrate to")
	assert.Equal(t, 1, logged.count("v0.36.0"), "the line names the removal release")
	assert.Equal(t, 1, logged.count("kdex-tech/host-manager#304"), "the line names the removal issue")
	assert.Equal(t, 1, logged.count(subjectHash(sub)), "the line names the caller by hash")
	assert.Zero(t, logged.count(sub+"\""), "the raw subject is never logged")
	assert.Equal(t, 1, logged.count("roles-host"), "the line names the host")

	getRolesAs(t, mux, "/-/roles/admin", sub+"-other", []string{"kdexroles:admin:read"})
	assert.Equal(t, 2, logged.count(msg), "another caller is logged on its own")
}

// Only a role that exists enters the log-once set: a caller probing
// /-/roles/{name} with names of its choosing grows neither the set nor the
// log, and a context naming no subject is one key, not one per role (#303
// quad).
func TestKDexRoles_LegacyGrantLogBounded(t *testing.T) {
	const msg = "deprecated kdexroles entitlement used"
	hh, mux, logged := kdexRolesHostLogged(t, "roles-host")

	for i := range 50 {
		rr := getRolesAs(t, mux, "/-/roles/missing-"+strconv.Itoa(i), "prober", []string{"kdexroles::read"})
		require.Equal(t, http.StatusNotFound, rr.Code)
	}
	assert.Zero(t, logged.count(msg))
	assert.Zero(t, hh.legacyRoleGrantCallers(), "a missing role never enters the set")

	// No subject in the context: one key, whatever the role.
	for _, name := range []string{"viewer", "admin"} {
		req := httptest.NewRequest("GET", "/-/roles/"+name, nil)
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"entitlements": []string{"kdexroles::read"}}))
		mux.ServeHTTP(httptest.NewRecorder(), req)
	}
	assert.Equal(t, 1, hh.legacyRoleGrantCallers())
	assert.Equal(t, 1, logged.count(msg))

	// The set is bounded; past the cap one line says further callers are
	// suppressed.
	for i := range maxLegacyRoleGrantCallers + 10 {
		getRolesAs(t, mux, "/-/roles/viewer", "caller-"+strconv.Itoa(i), []string{"kdexroles:viewer:read"})
	}
	assert.Equal(t, maxLegacyRoleGrantCallers, hh.legacyRoleGrantCallers())
	assert.Equal(t, maxLegacyRoleGrantCallers, logged.count(msg))
	assert.Equal(t, 1, logged.count("further deprecated-grant callers suppressed"))
}

// The log-once set is per host: one caller on two hosts is logged on each.
func TestKDexRoles_LegacyGrantLogPerHost(t *testing.T) {
	const msg = "deprecated kdexroles entitlement used"
	_, muxA, loggedA := kdexRolesHostLogged(t, "host-a")
	_, muxB, loggedB := kdexRolesHostLogged(t, "host-b")
	for range 2 {
		getRolesAs(t, muxA, "/-/roles", "same-caller", []string{"kdexroles::read"})
		getRolesAs(t, muxB, "/-/roles", "same-caller", []string{"kdexroles::read"})
	}
	assert.Equal(t, 1, loggedA.count(msg))
	assert.Equal(t, 1, loggedB.count(msg))
	assert.Equal(t, 1, loggedA.count("host-a"))
	assert.Equal(t, 1, loggedB.count("host-b"))
}

// GET /-/roles/{name} decides authorization BEFORE existence, so a denial never
// tells a caller which role names exist.
func TestKDexRoles_GetByName(t *testing.T) {
	mux := kdexRolesMux(t)

	rr := getRoles(t, mux, "/-/roles/viewer", []string{"roles:viewer:read"})
	require.Equal(t, http.StatusOK, rr.Code)
	var got auth.RoleInfo
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, testRoles[1], got)

	assert.Equal(t, http.StatusForbidden, getRoles(t, mux, "/-/roles/admin", []string{"roles:viewer:read"}).Code)
	assert.Equal(t, http.StatusForbidden, getRoles(t, mux, "/-/roles/viewer", []string{"pages::read"}).Code)
	assert.Equal(t, http.StatusForbidden, getRoles(t, mux, "/-/roles/missing", []string{"roles:viewer:read"}).Code,
		"a missing role is denied exactly like an existing one the caller may not read")
	assert.Equal(t, http.StatusNotFound, getRoles(t, mux, "/-/roles/missing", []string{"roles::read"}).Code)
	assert.Equal(t, http.StatusUnauthorized, getRoles(t, mux, "/-/roles/viewer", nil).Code)
}

// A ':' in the role name cannot name any KDexRole (Kubernetes object names
// have none). entitlements v0.7.0 errors on such an identity instead of
// matching nothing; the handler must still answer the ordinary denial, not a
// caller-triggerable 500 (the #195 class).
func TestKDexRoles_GetByNameWithColonIsDenied(t *testing.T) {
	mux := kdexRolesMux(t)
	for _, name := range []string{"a:b", "a%3Ab", "x@y:z"} {
		p := "/-/roles/" + name
		assert.Equal(t, http.StatusUnauthorized, getRoles(t, mux, p, nil).Code, "%s anonymous", p)
		for _, held := range [][]string{{"roles:viewer:read"}, {"roles::read"}, {"kdexroles:viewer:read"}, {"kdexroles::read"}} {
			assert.Equal(t, http.StatusForbidden, getRoles(t, mux, p, held).Code, "%s %v", p, held)
		}
	}
}

// The OpenAPI names the contract's grant and the deprecated alias (#303).
func TestKDexRoles_OpenAPISecurity(t *testing.T) {
	hh := &HostHandler{log: logr.Discard(), authChecker: auth.NewAuthorizationChecker(nil, logr.Discard())}
	ex, err := auth.NewExchanger(context.Background(), auth.Config{}, nil, roleListingProvider{roles: testRoles}, nil)
	require.NoError(t, err)
	hh.authExchanger = ex
	paths := map[string]ko.PathInfo{}
	hh.kdexRolesHandler(http.NewServeMux(), paths)
	for _, p := range []string{kdexRolesPath, kdexRolePath} {
		op := paths[p].API.Paths[p].Get
		require.NotNil(t, op, p)
		require.NotNil(t, op.Security, p)
		assert.Equal(t, []string{"roles:{name}:read"}, (*op.Security)[0]["bearer"], p)
		assert.Contains(t, op.Description, "kdexroles:<name>:read", p)
		assert.Contains(t, op.Description, "deprecated", p)
		assert.Contains(t, op.Description, "v0.36.0", p)
		assert.Contains(t, op.Description, "kdex-tech/host-manager#304", p)
	}
	assert.NotNil(t, paths[kdexRolePath].API.Paths[kdexRolePath].Get.Responses.Status(403),
		"a denied /-/roles/{name} is a 403")
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
