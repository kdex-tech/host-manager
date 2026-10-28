package auth

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// kindsBinding is a KDexRoleBinding on the rbc fixture host granting role to
// subject, narrowed to kinds when any are given. The fake client skips the
// CRD enum, so a kind this release does not know can be written directly.
func kindsBinding(name, subject, role string, kinds ...v1alpha1.SubjectKind) *v1alpha1.KDexRoleBinding {
	return &v1alpha1.KDexRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: rbcNamespace},
		Spec: v1alpha1.KDexRoleBindingSpec{
			HostRef:      v1.LocalObjectReference{Name: rbcFocalHost},
			Subject:      subject,
			Roles:        []string{role},
			SubjectKinds: kinds,
		},
	}
}

// newKindsScopeProvider builds a REAL scopeProvider over bindings, with one
// KDexRole per role they grant, so a result depends on the actual matcher.
func newKindsScopeProvider(t *testing.T, lookups []Lookup, bindings ...*v1alpha1.KDexRoleBinding) *scopeProvider {
	t.Helper()
	var objs []client.Object
	seen := map[string]bool{}
	for _, b := range bindings {
		objs = append(objs, b)
		for _, role := range b.Spec.Roles {
			if seen[role] {
				continue
			}
			seen[role] = true
			objs = append(objs, &v1alpha1.KDexRole{
				ObjectMeta: metav1.ObjectMeta{Name: role, Namespace: rbcNamespace},
				Spec: v1alpha1.KDexRoleSpec{
					HostRef: v1.LocalObjectReference{Name: rbcFocalHost},
					Rules:   []v1alpha1.PolicyRule{{Resources: []string{role}, Verbs: []string{"read"}}},
				},
			})
		}
	}
	sp, err := NewRoleProvider(context.Background(), newRBCClient(t, objs...), rbcFocalHost, rbcNamespace, lookups)
	require.NoError(t, err)
	return sp
}

// logCapture is what the swapped-in role-binding logger wrote.
type logCapture struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// captureRoleBindingLog swaps the role-binding logger for a funcr sink at
// verbosity v for the rest of the test. No test in this package runs in
// parallel, so the swap is safe.
func captureRoleBindingLog(t *testing.T, v int) *logCapture {
	t.Helper()
	c := &logCapture{}
	prev := bindingKeyLog
	bindingKeyLog = funcr.New(func(prefix, args string) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.buf.WriteString(prefix + " " + args + "\n")
	}, funcr.Options{Verbosity: v})
	t.Cleanup(func() { bindingKeyLog = prev })
	return c
}

// TestResolveRoles_SubjectKindMatrix pins Matching semantics over every
// subject form: a binding contributes iff its subject matches AND its
// subjectKinds is absent or lists the caller's kind. See #255.
func TestResolveRoles_SubjectKindMatrix(t *testing.T) {
	user, cl := v1alpha1.SubjectKindUser, v1alpha1.SubjectKindClient
	kindSets := []struct {
		name  string
		kinds []v1alpha1.SubjectKind
	}{
		{"absent", nil},
		{"[User]", []v1alpha1.SubjectKind{user}},
		{"[Client]", []v1alpha1.SubjectKind{cl}},
		{"[User, Client]", []v1alpha1.SubjectKind{user, cl}},
	}
	keyFor := map[v1alpha1.SubjectKind]string{user: "alice", cl: "svc-client"}
	forms := []struct {
		name    string
		subject func(key string) string
	}{
		{"exact", func(key string) string { return key }},
		{"*", func(string) string { return "*" }},
		{"/^.*$/", func(string) string { return "/^.*$/" }},
	}

	for _, form := range forms {
		results := map[string]map[v1alpha1.SubjectKind]bool{}
		for _, ks := range kindSets {
			results[ks.name] = map[v1alpha1.SubjectKind]bool{}
			for _, kind := range []v1alpha1.SubjectKind{user, cl} {
				key := keyFor[kind]
				sp := newKindsScopeProvider(t, nil, kindsBinding("b", form.subject(key), "r", ks.kinds...))

				var names BindingNames
				roles, _, err := sp.FindInternalRolesAndEntitlements(BindingSubject{Key: key, Kind: kind}, &names)
				require.NoError(t, err)

				want := ks.kinds == nil || slices.Contains(ks.kinds, kind)
				got := slices.Contains(roles, "r")
				results[ks.name][kind] = got
				assert.Equal(t, want, got, "%s binding, kinds %s, queried as %s", form.name, ks.name, kind)
				if want {
					assert.Equal(t, []string{"b"}, names.Contributed, "%s %s as %s", form.name, ks.name, kind)
					assert.Empty(t, names.SkippedForKind, "%s %s as %s", form.name, ks.name, kind)
				} else {
					assert.Empty(t, names.Contributed, "%s %s as %s", form.name, ks.name, kind)
					assert.Equal(t, []string{"b"}, names.SkippedForKind, "%s %s as %s", form.name, ks.name, kind)
				}
			}
		}
		assert.Equal(t, results["absent"], results["[User, Client]"],
			"%s: absent and [User, Client] must give identical results for both kinds", form.name)
	}
}

// TestResolveRoles_UnknownBindingKindIsDeadEntry pins fail-closed, per entry:
// a kind this release does not know never equals a subject's kind, while the
// list's other entries still apply. An all-unknown list stays narrowed and so
// matches nothing; it never collapses into "any kind".
func TestResolveRoles_UnknownBindingKindIsDeadEntry(t *testing.T) {
	sp := newKindsScopeProvider(t, nil,
		kindsBinding("user-or-sa", "*", "user-role", "User", "ServiceAccount"),
		kindsBinding("sa-only", "*", "sa-role", "ServiceAccount"),
	)

	resolve := func(kind v1alpha1.SubjectKind) []string {
		roles, _, err := sp.FindInternalRolesAndEntitlements(BindingSubject{Key: "alice", Kind: kind}, nil)
		require.NoError(t, err)
		return roles
	}

	assert.Equal(t, []string{"user-role"}, resolve(v1alpha1.SubjectKindUser),
		"a known entry still applies beside an unknown one")
	assert.Empty(t, resolve(v1alpha1.SubjectKindClient))
	assert.Empty(t, resolve("ServiceAccount"),
		"an unknown kind never matches a narrowed binding, even one listing it")

	for _, pb := range sp.patternBindings {
		if pb.name == "sa-only" {
			assert.True(t, pb.narrowed, "an all-unknown list is narrowed, not 'any kind'")
		}
	}
}

// TestResolveRoles_UnknownSubjectKindMatchesOnlyUnnarrowed pins the other
// half: a subject whose kind is unknown or empty gets the bindings without
// subjectKinds and none narrowed to a kind.
//
// Only an EMPTY kind is logged at V(0): it marks a site that lost track of its
// subject's kind. A non-empty unknown kind, such as a ServiceAccount a newer
// release recorded, is a credential carrying its kind correctly, so it is
// logged on the site's own resolution line and level.
func TestResolveRoles_UnknownSubjectKindMatchesOnlyUnnarrowed(t *testing.T) {
	sp := newKindsScopeProvider(t, nil,
		kindsBinding("anyone", "*", "any-role"),
		kindsBinding("users", "*", "user-role", v1alpha1.SubjectKindUser),
		kindsBinding("clients", "*", "client-role", v1alpha1.SubjectKindClient),
	)
	ex, err := NewExchanger(context.Background(), Config{}, nil, sp, nil)
	require.NoError(t, err)

	resolve := func(kind v1alpha1.SubjectKind, v int) (string, []string) {
		out := captureRoleBindingLog(t, v)
		roles, _, err := ex.ResolveInternalRolesAndEntitlements(BindingSubject{Key: "alice", Kind: kind, Site: SiteWhoami})
		require.NoError(t, err)
		assert.NotContains(t, out.String(), "alice")
		return out.String(), roles
	}

	t.Run("empty", func(t *testing.T) {
		out, roles := resolve("", 0)
		assert.Equal(t, []string{"any-role"}, roles)
		assert.Contains(t, out, `"site"="whoami"`, "an empty kind is logged at V(0)")
	})

	t.Run("non-empty unknown", func(t *testing.T) {
		out, roles := resolve("ServiceAccount", 0)
		assert.Equal(t, []string{"any-role"}, roles)
		assert.Empty(t, out, "a recorded unknown kind is not a V(0) event")

		out, _ = resolve("ServiceAccount", bindingLogLevel(SiteWhoami))
		assert.Contains(t, out, `"kind"="ServiceAccount"`, "it is logged on the site's own line")
		assert.Contains(t, out, `"contributed"=["anyone"]`)
	})
}

// TestResolveRoles_LogNeverCarriesKey pins Logging: the role-binding line
// names the site, the kind and the bindings, never the lookup key, which may
// be an email (#215).
func TestResolveRoles_LogNeverCarriesKey(t *testing.T) {
	const key = "alice@example.com"
	sp := newKindsScopeProvider(t, nil,
		kindsBinding("clients-only", key, "client-role", v1alpha1.SubjectKindClient),
		kindsBinding("everyone", "*", "any-role"),
	)
	ex, err := NewExchanger(context.Background(), Config{}, nil, sp, nil)
	require.NoError(t, err)

	out := captureRoleBindingLog(t, 3)
	roles, _, err := ex.ResolveInternalRolesAndEntitlements(
		BindingSubject{Key: key, Kind: v1alpha1.SubjectKindUser, Site: SiteHostPAT})
	require.NoError(t, err)
	assert.Equal(t, []string{"any-role"}, roles)

	got := out.String()
	assert.Contains(t, got, `"site"="host pat"`)
	assert.Contains(t, got, `"kind"="User"`)
	assert.Contains(t, got, `"contributed"=["everyone"]`)
	assert.Contains(t, got, `"skipped_for_kind"=["clients-only"]`,
		"the binding whose subject matched but whose kinds did not is reported as skipped")
	assert.NotContains(t, got, key, "the lookup key is never logged")
}

// TestResolveRoles_NoCollectorNoAllocs pins Cost: with no collector the
// matcher allocates nothing for kinds, so a narrowed set costs what the
// absent-kinds set does.
func TestResolveRoles_NoCollectorNoAllocs(t *testing.T) {
	bindings := func(kinds ...v1alpha1.SubjectKind) []*v1alpha1.KDexRoleBinding {
		return []*v1alpha1.KDexRoleBinding{
			kindsBinding("exact", "alice", "r1", kinds...),
			kindsBinding("wildcard", "*", "r2", kinds...),
			kindsBinding("regex", "/^al/", "r3", kinds...),
		}
	}
	base := newKindsScopeProvider(t, nil, bindings()...)
	narrowed := newKindsScopeProvider(t, nil, bindings(v1alpha1.SubjectKindUser)...)
	bs := BindingSubject{Key: "alice", Kind: v1alpha1.SubjectKindUser}

	require.ElementsMatch(t, base.resolveRoles(bs, nil), narrowed.resolveRoles(bs, nil))

	baseAllocs := testing.AllocsPerRun(100, func() { _ = base.resolveRoles(bs, nil) })
	narrowedAllocs := testing.AllocsPerRun(100, func() { _ = narrowed.resolveRoles(bs, nil) })
	assert.LessOrEqual(t, narrowedAllocs, baseAllocs,
		"a narrowed binding set must add no allocation when no collector is passed")

	// The entry point hands over a collector only when the site's line is
	// enabled: with the role-binding logger below V(2) it costs exactly a
	// collector-less resolve.
	ex, err := NewExchanger(context.Background(), Config{}, nil, narrowed, nil)
	require.NoError(t, err)
	captureRoleBindingLog(t, 0)
	direct := testing.AllocsPerRun(100, func() { _, _, _ = narrowed.FindInternalRolesAndEntitlements(bs, nil) })
	bs.Site = SiteOIDCLogin
	viaEntry := testing.AllocsPerRun(100, func() { _, _, _ = ex.ResolveInternalRolesAndEntitlements(bs) })
	assert.Equal(t, direct, viaEntry, "with the logger off the entry point collects no binding names")
}
