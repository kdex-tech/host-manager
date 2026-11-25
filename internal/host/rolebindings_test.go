package host

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	rbHost      = "rb-host"
	rbNamespace = "rb-ns"
)

func rbBinding(name, host, subject string, roles []string, kinds ...kdexv1alpha1.SubjectKind) *kdexv1alpha1.KDexRoleBinding {
	return &kdexv1alpha1.KDexRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: rbNamespace},
		Spec: kdexv1alpha1.KDexRoleBindingSpec{
			HostRef:      corev1.LocalObjectReference{Name: host},
			Subject:      subject,
			Roles:        roles,
			SubjectKinds: kinds,
		},
	}
}

// rbFixture is the binding table most tests use.
func rbFixture() []*kdexv1alpha1.KDexRoleBinding {
	return []*kdexv1alpha1.KDexRoleBinding{
		rbBinding("alice-exact", rbHost, "alice", []string{"viewer", "editor"}),
		rbBinding("everyone", rbHost, "*", []string{"viewer"}),
		rbBinding("admins", rbHost, "/^adm/", []string{"admin"}, kdexv1alpha1.SubjectKindUser),
		rbBinding("clients", rbHost, "/^.*$/", []string{"svc"}, kdexv1alpha1.SubjectKindClient),
		rbBinding("broken", rbHost, "/(/", []string{"never"}),
		rbBinding("other-host", "elsewhere", "alice", []string{"foreign"}),
	}
}

// rbProvider is the REAL role provider over a fake client. Once it is built,
// every List fails and is counted: the route must answer from the table
// compiled at reconcile, never from the API server (#303).
func rbProvider(t *testing.T, bindings []*kdexv1alpha1.KDexRoleBinding) (auth.InternalIdentityProvider, *atomic.Int32) {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, kdexv1alpha1.AddToScheme(s))
	objs := make([]client.Object, 0, len(bindings))
	for _, b := range bindings {
		objs = append(objs, b)
	}
	byHost := func(o client.Object) []string {
		switch v := o.(type) {
		case *kdexv1alpha1.KDexRoleBinding:
			return []string{v.Spec.HostRef.Name}
		case *kdexv1alpha1.KDexRole:
			return []string{v.Spec.HostRef.Name}
		}
		return nil
	}
	var built atomic.Bool
	lists := &atomic.Int32{}
	base := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&kdexv1alpha1.KDexRoleBinding{}, internal.HOST_INDEX_KEY, byHost).
		WithIndex(&kdexv1alpha1.KDexRole{}, internal.HOST_INDEX_KEY, byHost).
		WithObjects(objs...).Build()
	c := interceptor.NewClient(base, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, l client.ObjectList, opts ...client.ListOption) error {
			if built.Load() {
				lists.Add(1)
				return errors.New("no API call after the provider is compiled")
			}
			return c.List(ctx, l, opts...)
		},
	})
	sp, err := auth.NewRoleProvider(context.Background(), c, rbHost, rbNamespace, nil)
	require.NoError(t, err)
	built.Store(true)
	return sp, lists
}

func roleBindingsHandler(t *testing.T, bindings []*kdexv1alpha1.KDexRoleBinding) (*HostHandler, *http.ServeMux, map[string]ko.PathInfo, *atomic.Int32) {
	t.Helper()
	sp, lists := rbProvider(t, bindings)
	hh, mux, paths := roleBindingsHandlerWith(t, sp)
	return hh, mux, paths, lists
}

// roleBindingsHandlerWith serves /-/rolebindings over the identity provider sp.
func roleBindingsHandlerWith(t *testing.T, sp auth.InternalIdentityProvider) (*HostHandler, *http.ServeMux, map[string]ko.PathInfo) {
	t.Helper()
	ex, err := auth.NewExchanger(context.Background(), auth.Config{}, nil, sp, nil)
	require.NoError(t, err)
	hh := &HostHandler{
		log:    logr.Discard(),
		scheme: "https",
		// ActivePair makes auth enabled, so the response is private.
		authConfig:    &auth.Config{ActivePair: &keys.KeyPair{}},
		authChecker:   auth.NewAuthorizationChecker(nil, logr.Discard()),
		authExchanger: ex,
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{"rb.example"}},
		},
	}
	mux := http.NewServeMux()
	paths := map[string]ko.PathInfo{}
	hh.roleBindingsHandler(mux, paths)
	return hh, mux, paths
}

// countingMatcher is a binding matcher that counts the subjects it matches.
type countingMatcher struct {
	roleListingProvider
	digest  string
	matched *atomic.Int32
}

func (m countingMatcher) MatchBindings(key string, kind kdexv1alpha1.SubjectKind) []auth.MatchedBinding {
	m.matched.Add(1)
	return []auth.MatchedBinding{{Name: "b-" + key, Subject: key, Admitted: true, Roles: []string{"r"}}}
}

func (m countingMatcher) BindingsDigest() string { return m.digest }

func roleBindingsMux(t *testing.T) *http.ServeMux {
	t.Helper()
	_, mux, _, _ := roleBindingsHandler(t, rbFixture())
	return mux
}

// held == nil means no auth context at all (anonymous).
func getRoleBindings(t *testing.T, mux *http.ServeMux, query string, held []string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/-/rolebindings"+query, nil)
	if held != nil {
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "role-service", "entitlements": held}))
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func decodeRoleBindings(t *testing.T, rr *httptest.ResponseRecorder) roleBindingsResponse {
	t.Helper()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var body roleBindingsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
	return body
}

func bindingNamesOf(s subjectBindings) []string {
	out := []string{}
	for _, b := range s.Bindings {
		out = append(out, b.Name)
	}
	return out
}

// rbScope is the grants of a caller holding the gate: the kdex-roles
// contract's opaque role_assignments_read.
var rbScope = []string{roleAssignmentsReadScope}

// A caller holding role_assignments_read sees every matching binding (#303).
func TestRoleBindings_ScopeSeesEveryBinding(t *testing.T) {
	mux := roleBindingsMux(t)

	body := decodeRoleBindings(t, getRoleBindings(t, mux, "?subject=alice&kind=User", rbScope))
	require.Len(t, body.Subjects, 1)
	s := body.Subjects[0]
	assert.Equal(t, "alice", s.Subject)
	assert.Equal(t, "User", s.Kind)
	// Sorted by name; the other host's and the non-compiling binding are absent.
	assert.Equal(t, []string{"alice-exact", "clients", "everyone"}, bindingNamesOf(s))
	byName := map[string]auth.MatchedBinding{}
	for _, b := range s.Bindings {
		byName[b.Name] = b
	}
	assert.Equal(t, auth.MatchedBinding{Name: "alice-exact", Subject: "alice", Admitted: true, Roles: []string{"viewer", "editor"}}, byName["alice-exact"])
	assert.Equal(t, auth.MatchedBinding{Name: "clients", Subject: "/^.*$/", Admitted: false, CoverAll: true, Roles: []string{"svc"}}, byName["clients"])
	assert.Equal(t, auth.MatchedBinding{Name: "everyone", Subject: "*", Admitted: true, CoverAll: true, Roles: []string{"viewer"}}, byName["everyone"])
	// Union over ADMITTED bindings, sorted and de-duplicated.
	assert.Equal(t, []string{"editor", "viewer"}, s.Roles)
}

// Repeated subjects are answered in request order, each on its own.
func TestRoleBindings_MultipleSubjects(t *testing.T) {
	body := decodeRoleBindings(t, getRoleBindings(t, roleBindingsMux(t),
		"?subject=admin-1&subject=alice&subject=admin-1&kind=User", rbScope))
	require.Len(t, body.Subjects, 3)
	assert.Equal(t, "admin-1", body.Subjects[0].Subject)
	assert.Equal(t, []string{"admins", "clients", "everyone"}, bindingNamesOf(body.Subjects[0]))
	assert.Equal(t, []string{"admin", "viewer"}, body.Subjects[0].Roles)
	assert.Equal(t, "alice", body.Subjects[1].Subject)
	assert.Equal(t, []string{"editor", "viewer"}, body.Subjects[1].Roles)
	assert.Equal(t, body.Subjects[0], body.Subjects[2])
}

// kind absent is "": only bindings without subjectKinds admit it.
func TestRoleBindings_KindAbsentFollowsUnknownKindRule(t *testing.T) {
	mux := roleBindingsMux(t)
	body := decodeRoleBindings(t, getRoleBindings(t, mux, "?subject=admin-1", rbScope))
	s := body.Subjects[0]
	assert.Equal(t, "", s.Kind)
	assert.Equal(t, []string{"admins", "clients", "everyone"}, bindingNamesOf(s))
	for _, b := range s.Bindings {
		assert.Equal(t, b.Name == "everyone", b.Admitted, b.Name)
	}
	assert.Equal(t, []string{"viewer"}, s.Roles)

	body = decodeRoleBindings(t, getRoleBindings(t, mux, "?subject=svc-1&kind=Client", rbScope))
	assert.Equal(t, []string{"svc", "viewer"}, body.Subjects[0].Roles)
}

// Unauthenticated is 401. An authenticated caller without
// role_assignments_read is 403: all or nothing, so an answer is never a
// partial view (#303). The opaque scope is matched by exact name: no
// wildcard, `all` or neighbouring grant implies it.
func TestRoleBindings_AnonymousAndUnscoped(t *testing.T) {
	mux := roleBindingsMux(t)

	rr := getRoleBindings(t, mux, "?subject=alice", nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("WWW-Authenticate"))

	for _, held := range [][]string{
		{}, {"pages::read"}, {"roles::read"}, {"roles::all"}, {"kdexroles::read"},
		{"rolebindings::read"}, {"rolebindings:alice-exact:read"},
		{"role_assignments_update"}, {"roles_list"}, {"role_assignments_read:x:read"},
	} {
		rr := getRoleBindings(t, mux, "?subject=alice&subject=admin-1&kind=User", held)
		assert.Equal(t, http.StatusForbidden, rr.Code, "%v", held)
		assert.NotContains(t, rr.Body.String(), "alice-exact", "%v", held)
	}
}

// A subject no binding matches is 200 with [] (not null): with the scope, an
// empty answer means "no static roles".
func TestRoleBindings_NoMatchIsEmptyNotNull(t *testing.T) {
	_, mux, _, _ := roleBindingsHandler(t, nil)
	rr := getRoleBindings(t, mux, "?subject=alice", rbScope)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"subjects":[{"subject":"alice","kind":"","bindings":[],"roles":[]}]}`, rr.Body.String())
}

// Only bad parameters are 400: they bound the regex work one request does.
func TestRoleBindings_BadParameters(t *testing.T) {
	mux := roleBindingsMux(t)
	many := url.Values{}
	for i := range maxRoleBindingSubjects + 1 {
		many.Add("subject", "s"+string(rune('a'+i%26)))
	}
	atCap := url.Values{}
	for range maxRoleBindingSubjects {
		atCap.Add("subject", "alice")
	}
	long := strings.Repeat("x", maxRoleBindingSubjectLen+1)
	// Each subject within its own limit, together over the total.
	overTotal, atTotal := url.Values{}, url.Values{}
	for i := range maxRoleBindingSubjectBytes/maxRoleBindingSubjectLen + 1 {
		overTotal.Add("subject", strings.Repeat(string(rune('a'+i)), maxRoleBindingSubjectLen))
	}
	for i := range maxRoleBindingSubjectBytes / maxRoleBindingSubjectLen {
		atTotal.Add("subject", strings.Repeat(string(rune('a'+i)), maxRoleBindingSubjectLen))
	}
	for name, q := range map[string]string{
		"no subject":        "",
		"kind only":         "?kind=User",
		"empty subject":     "?subject=",
		"one empty subject": "?subject=alice&subject=",
		"too many subjects": "?" + many.Encode(),
		"subject too long":  "?subject=" + long,
		"kind repeated":     "?subject=alice&kind=User&kind=Client",
		"kind too long":     "?subject=alice&kind=" + strings.Repeat("k", maxRoleBindingKindLen+1),
		"subjects too big":  "?" + overTotal.Encode(),
	} {
		rr := getRoleBindings(t, mux, q, rbScope)
		assert.Equal(t, http.StatusBadRequest, rr.Code, name)
	}
	assert.Equal(t, http.StatusOK, getRoleBindings(t, mux, "?"+atCap.Encode(), rbScope).Code)
	assert.Equal(t, http.StatusOK, getRoleBindings(t, mux, "?subject="+strings.Repeat("x", maxRoleBindingSubjectLen), rbScope).Code)
	assert.Equal(t, http.StatusOK, getRoleBindings(t, mux, "?"+atTotal.Encode(), rbScope).Code)
	assert.Equal(t, http.StatusOK, getRoleBindings(t, mux, "?subject=alice&kind="+strings.Repeat("k", maxRoleBindingKindLen), rbScope).Code)
	// Authorization is decided first: an anonymous bad request is a 401, an
	// unscoped one a 403.
	assert.Equal(t, http.StatusUnauthorized, getRoleBindings(t, mux, "", nil).Code)
	assert.Equal(t, http.StatusForbidden, getRoleBindings(t, mux, "", []string{"pages::read"}).Code)
}

// The response is private and never stored, as /-/roles; its ETag moves with
// the binding table and with the caller (#303), so a non-browser caller that
// keeps its own copy can still revalidate it.
func TestRoleBindings_Caching(t *testing.T) {
	_, mux, _, _ := roleBindingsHandler(t, rbFixture())
	held := rbScope

	rr := getRoleBindings(t, mux, "?subject=alice", held)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, noStoreCacheControl, rr.Header().Get("Cache-Control"), "parity with /-/roles")
	assert.Contains(t, strings.Join(rr.Header().Values("Vary"), ","), "Authorization")
	etag := rr.Header().Get("ETag")
	require.NotEmpty(t, etag)

	rr = getRoleBindings(t, mux, "?subject=alice", held, "If-None-Match", etag)
	assert.Equal(t, http.StatusNotModified, rr.Code)
	assert.Empty(t, rr.Body.String())
	assert.Equal(t, noStoreCacheControl, rr.Header().Get("Cache-Control"), "a 304 carries the same Cache-Control")

	other := getRoleBindings(t, mux, "?subject=alice", []string{roleAssignmentsReadScope, "pages::read"})
	assert.NotEqual(t, etag, other.Header().Get("ETag"), "another caller, another ETag")

	changed := rbFixture()
	changed[1].Spec.Roles = []string{"viewer", "commenter"}
	_, mux2, _, _ := roleBindingsHandler(t, changed)
	rr = getRoleBindings(t, mux2, "?subject=alice", held, "If-None-Match", etag)
	assert.Equal(t, http.StatusOK, rr.Code, "a binding change must not revalidate the old body")
	assert.NotEqual(t, etag, rr.Header().Get("ETag"))
}

// Requests are answered from the table compiled at reconcile: none reaches
// the API server (#303).
func TestRoleBindings_NoAPICallPerRequest(t *testing.T) {
	_, mux, _, lists := roleBindingsHandler(t, rbFixture())
	for range 3 {
		decodeRoleBindings(t, getRoleBindings(t, mux, "?subject=alice&subject=admin-1&kind=User", rbScope))
	}
	assert.Zero(t, lists.Load())
}

func TestRoleBindings_OpenAPIRegistered(t *testing.T) {
	_, _, paths, _ := roleBindingsHandler(t, rbFixture())
	info, ok := paths[roleBindingsPath]
	require.True(t, ok, "the route must be registered so it appears in /-/openapi")
	assert.Equal(t, ko.SystemPathType, info.Type)
	op := info.API.Paths[roleBindingsPath].Get
	require.NotNil(t, op)
	assert.Contains(t, op.Description, "compiled")
	assert.NotNil(t, op.Responses.Status(200))
	assert.NotNil(t, op.Responses.Status(400))
	assert.NotNil(t, op.Responses.Status(401))
	assert.NotNil(t, op.Responses.Status(403))
	assert.NotNil(t, op.Responses.Status(503))
	require.NotNil(t, op.Security)
	assert.Equal(t, []string{roleAssignmentsReadScope}, (*op.Security)[0]["bearer"])
	assert.Contains(t, op.Description, roleAssignmentsReadScope)
	schema := op.Responses.Status(200).Value.Content.Get("application/json").Schema.Value
	assert.NotContains(t, schema.Properties, "visible")
	assert.NotContains(t, schema.Properties, "complete")
	var names []string
	for _, p := range op.Parameters {
		names = append(names, p.Value.Name)
	}
	assert.ElementsMatch(t, []string{"subject", "kind"}, names)
}

// With auth disabled (no checker) there is nothing to gate on, so the route
// is not registered at all, as for /-/roles.
func TestRoleBindings_NotRegisteredWithoutAuth(t *testing.T) {
	hh := &HostHandler{log: logr.Discard()}
	mux := http.NewServeMux()
	paths := map[string]ko.PathInfo{}
	hh.roleBindingsHandler(mux, paths)
	assert.Empty(t, paths)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/-/rolebindings?subject=alice", nil))
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// The ETag is decided before any matching, so a revalidation that answers 304
// costs no regex work; and it carries the query, so one query's ETag never
// revalidates another's body (#303 quad).
func TestRoleBindings_NotModifiedBeforeMatching(t *testing.T) {
	matched := &atomic.Int32{}
	_, mux, _ := roleBindingsHandlerWith(t, countingMatcher{digest: "d1", matched: matched})

	rr := getRoleBindings(t, mux, "?subject=alice&subject=bob&kind=User", rbScope)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, int32(2), matched.Load())
	etag := rr.Header().Get("ETag")
	require.NotEmpty(t, etag)

	rr = getRoleBindings(t, mux, "?subject=alice&subject=bob&kind=User", rbScope, "If-None-Match", etag)
	assert.Equal(t, http.StatusNotModified, rr.Code)
	assert.Equal(t, int32(2), matched.Load(), "a 304 must not run the matcher")

	for _, q := range []string{
		"?subject=alice",
		"?subject=bob&subject=alice&kind=User",
		"?subject=alice&subject=bob",
		"?subject=alice&subject=bob&kind=Client",
		"?subject=alice%26subject%3Dbob&kind=User",
	} {
		rr := getRoleBindings(t, mux, q, rbScope, "If-None-Match", etag)
		assert.Equal(t, http.StatusOK, rr.Code, q)
		assert.NotEqual(t, etag, rr.Header().Get("ETag"), "another query, another ETag: %s", q)
	}
}

// A reconcile that leaves the bindings as they were keeps the ETag, so a
// caller's copy still revalidates to a 304: the ETag is anchored to the
// bindings, not to the host's reconcile time (#303 quad).
func TestRoleBindings_ETagStableAcrossReconciles(t *testing.T) {
	cacheManager, err := cache.NewCacheManager("", rbHost, nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, rbHost, rbNamespace, logr.Discard(), cacheManager)
	reconcile := func(bindings []*kdexv1alpha1.KDexRoleBinding, at time.Time) {
		sp, _ := rbProvider(t, bindings)
		ex, err := auth.NewExchanger(context.Background(), auth.Config{}, nil, sp, nil)
		require.NoError(t, err)
		hh.SetHost(context.Background(), &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{"rb.example"}},
		}, &kdexv1alpha1.KDexObjectStatus{}, nil, nil, nil, "", nil, nil, ex,
			&auth.Config{ActivePair: &keys.KeyPair{}}, "https", nil, at)
	}
	get := func(header ...string) *httptest.ResponseRecorder {
		hh.mu.RLock()
		mux := hh.Mux
		hh.mu.RUnlock()
		return getRoleBindings(t, mux, "?subject=alice&kind=User", rbScope, header...)
	}

	t0 := time.Now().Add(-time.Hour)
	reconcile(rbFixture(), t0)
	rr := get()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	etag := rr.Header().Get("ETag")
	require.NotEmpty(t, etag)

	reconcile(rbFixture(), t0.Add(time.Minute))
	rr = get("If-None-Match", etag)
	assert.Equal(t, http.StatusNotModified, rr.Code, "identical bindings: same ETag")
	assert.Equal(t, etag, rr.Header().Get("ETag"))

	changed := rbFixture()
	changed[0].Spec.Roles = []string{"viewer"}
	reconcile(changed, t0.Add(2*time.Minute))
	rr = get("If-None-Match", etag)
	assert.Equal(t, http.StatusOK, rr.Code, "changed bindings: new ETag")
	assert.NotEqual(t, etag, rr.Header().Get("ETag"))
}

// Last-Modified moves forward on every binding change, even two in one
// second, so If-Modified-Since never revalidates a newer table (#303 quad).
func TestRoleBindingsLastModified_Monotonic(t *testing.T) {
	hh := &HostHandler{}
	a := hh.roleBindingsLastModified("d1")
	assert.Equal(t, a, hh.roleBindingsLastModified("d1"), "same digest, same time")
	b := hh.roleBindingsLastModified("d2")
	assert.True(t, b.After(a), "a new digest moves Last-Modified forward")
	c := hh.roleBindingsLastModified("d1")
	assert.True(t, c.After(b), "returning to an older digest is still a change")
}

// Without a binding matcher the host cannot tell what binds a subject: 503,
// never a 200 that would claim "no static roles" (#303 quad).
func TestRoleBindings_NoMatcherIs503(t *testing.T) {
	_, mux, _ := roleBindingsHandlerWith(t, roleListingProvider{roles: testRoles})
	rr := getRoleBindings(t, mux, "?subject=alice", rbScope)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.NotContains(t, rr.Body.String(), "subjects")
	assert.Empty(t, rr.Header().Get("ETag"))
	// Authorization still comes first.
	assert.Equal(t, http.StatusForbidden, getRoleBindings(t, mux, "?subject=alice", []string{"pages::read"}).Code)
}
