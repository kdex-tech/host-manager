package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func matchedNames(ms []MatchedBinding) []string {
	out := []string{}
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

// MatchBindings answers with exactly the rule resolveRoles enforces: the same
// compiled table, the same subject syntax, the same kind admission (#303).
func TestMatchBindings_SubjectSyntax(t *testing.T) {
	sp := newKindsScopeProvider(t, nil,
		kindsBinding("exact", "alice", "r-exact"),
		kindsBinding("wildcard", "*", "r-wild"),
		kindsBinding("regex", "/^al/", "r-regex"),
		kindsBinding("unanchored", "/ice/", "r-unanchored"),
		// len > 2 boundary: "//" and "/" are not regexes, they match byte-exact.
		kindsBinding("empty-slashes", "//", "r-slashes"),
		kindsBinding("one-slash", "/", "r-slash"),
		kindsBinding("shortest-regex", "/a/", "r-shortest"),
		// A regex that does not compile is skipped, the others kept.
		kindsBinding("broken", "/(/", "r-broken"),
	)

	tests := []struct {
		key  string
		want []string
	}{
		{"alice", []string{"exact", "regex", "shortest-regex", "unanchored", "wildcard"}},
		{"bob", []string{"wildcard"}},
		{"malice", []string{"shortest-regex", "unanchored", "wildcard"}},
		{"//", []string{"empty-slashes", "wildcard"}},
		{"/", []string{"one-slash", "wildcard"}},
		{"(", []string{"wildcard"}},
		{"/(/", []string{"wildcard"}},
		{"", []string{"wildcard"}},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := sp.MatchBindings(tt.key, v1alpha1.SubjectKindUser)
			assert.Equal(t, tt.want, matchedNames(got), "sorted by name")
			for _, m := range got {
				assert.True(t, m.Admitted, m.Name)
			}
		})
	}

	got := sp.MatchBindings("alice", v1alpha1.SubjectKindUser)
	byName := map[string]MatchedBinding{}
	for _, m := range got {
		byName[m.Name] = m
	}
	assert.Equal(t, MatchedBinding{Name: "exact", Subject: "alice", Admitted: true, Roles: []string{"r-exact"}}, byName["exact"])
	assert.Equal(t, MatchedBinding{Name: "wildcard", Subject: "*", Admitted: true, CoverAll: true, Roles: []string{"r-wild"}}, byName["wildcard"])
	assert.Equal(t, "/^al/", byName["regex"].Subject, "the pattern as written")
	assert.False(t, byName["regex"].CoverAll)
}

// Only the focal host's bindings are compiled, so only they can match.
func TestMatchBindings_HostFilter(t *testing.T) {
	other := kindsBinding("elsewhere", "alice", "r-other")
	other.Spec.HostRef = v1.LocalObjectReference{Name: "other-host"}
	sp := newKindsScopeProvider(t, nil, kindsBinding("here", "alice", "r-here"), other)
	assert.Equal(t, []string{"here"}, matchedNames(sp.MatchBindings("alice", v1alpha1.SubjectKindUser)))
}

// A matched binding whose subjectKinds excludes the kind is still reported,
// with admitted=false, exactly as resolveRoles records it skipped.
func TestMatchBindings_SubjectKinds(t *testing.T) {
	sp := newKindsScopeProvider(t, nil,
		kindsBinding("any", "alice", "r-any"),
		kindsBinding("users", "alice", "r-users", v1alpha1.SubjectKindUser),
		kindsBinding("clients", "*", "r-clients", v1alpha1.SubjectKindClient),
		kindsBinding("dead", "/a/", "r-dead", v1alpha1.SubjectKind("Robot")),
	)
	admitted := func(kind v1alpha1.SubjectKind) map[string]bool {
		out := map[string]bool{}
		for _, m := range sp.MatchBindings("alice", kind) {
			out[m.Name] = m.Admitted
		}
		return out
	}
	all := map[string]bool{"any": true, "users": true, "clients": false, "dead": false}
	assert.Equal(t, all, admitted(v1alpha1.SubjectKindUser))
	assert.Equal(t, map[string]bool{"any": true, "users": false, "clients": true, "dead": false}, admitted(v1alpha1.SubjectKindClient))
	// "" and an unknown kind follow the unknown-kind rule: only bindings
	// without subjectKinds admit them, even one listing that unknown value.
	unknown := map[string]bool{"any": true, "users": false, "clients": false, "dead": false}
	assert.Equal(t, unknown, admitted(""))
	assert.Equal(t, unknown, admitted(v1alpha1.SubjectKind("Robot")))
}

// resolveRoles and MatchBindings walk the same table: the roles of the
// admitted matches are exactly the roles resolveRoles returns, and the
// non-admitted matches exactly what it records as skipped for kind.
func TestMatchBindings_AgreesWithResolveRoles(t *testing.T) {
	sp := newKindsScopeProvider(t, nil,
		kindsBinding("a-exact", "alice", "r1"),
		kindsBinding("b-wild", "*", "r2", v1alpha1.SubjectKindClient),
		kindsBinding("c-regex", "/li/", "r3", v1alpha1.SubjectKindUser),
		kindsBinding("d-regex", "/^bob$/", "r4"),
	)
	for _, kind := range []v1alpha1.SubjectKind{v1alpha1.SubjectKindUser, v1alpha1.SubjectKindClient, ""} {
		for _, key := range []string{"alice", "bob", "carol"} {
			var names BindingNames
			roles := sp.resolveRoles(BindingSubject{Key: key, Kind: kind}, &names)
			var wantRoles, contributed, skipped []string
			for _, m := range sp.MatchBindings(key, kind) {
				if m.Admitted {
					wantRoles = append(wantRoles, m.Roles...)
					contributed = append(contributed, m.Name)
				} else {
					skipped = append(skipped, m.Name)
				}
			}
			assert.ElementsMatch(t, wantRoles, roles, "%s/%s", key, kind)
			assert.ElementsMatch(t, contributed, names.Contributed, "%s/%s", key, kind)
			assert.ElementsMatch(t, skipped, names.SkippedForKind, "%s/%s", key, kind)
		}
	}
}

// The returned roles are the caller's: mutating them must not reach the table.
func TestMatchBindings_RolesAreCopies(t *testing.T) {
	sp := newKindsScopeProvider(t, nil, kindsBinding("exact", "alice", "r1"))
	got := sp.MatchBindings("alice", v1alpha1.SubjectKindUser)
	require.Len(t, got, 1)
	got[0].Roles[0] = "tampered"
	assert.Equal(t, []string{"r1"}, sp.resolveRoles(BindingSubject{Key: "alice", Kind: v1alpha1.SubjectKindUser}, nil))
}

func TestRegexCoversAll(t *testing.T) {
	for expr, want := range map[string]bool{
		`.*`:       true,
		`^.*$`:     true,
		`(?s).*`:   true,
		`\A.*\z`:   true,
		`(?m)^.*$`: true,
		`(?:.*)`:   true,
		`.*?`:      true,
		`.+`:       false,
		`^a.*`:     false,
		`x`:        false,
		`.*x`:      false,
		`^$`:       false,
		`a|.*`:     false, // conservative: an alternation is never judged
		`[^\n]*`:   false, // conservative: a class is not judged, though it spells `.`
	} {
		t.Run(expr, func(t *testing.T) {
			assert.Equal(t, want, regexCoversAll(expr))
		})
	}
}

// The digest moves whenever a binding's matching input moves, and only then:
// it seeds the /-/rolebindings ETag.
func TestBindingsDigest(t *testing.T) {
	digest := func(bs ...*v1alpha1.KDexRoleBinding) string {
		return newKindsScopeProvider(t, nil, bs...).BindingsDigest()
	}
	base := digest(kindsBinding("a", "alice", "r1"), kindsBinding("b", "*", "r2"))
	require.NotEmpty(t, base)
	assert.Equal(t, base, digest(kindsBinding("b", "*", "r2"), kindsBinding("a", "alice", "r1")), "order-independent")
	assert.NotEqual(t, base, digest(kindsBinding("a", "alicia", "r1"), kindsBinding("b", "*", "r2")), "subject")
	assert.NotEqual(t, base, digest(kindsBinding("a", "alice", "r3"), kindsBinding("b", "*", "r2")), "roles")
	assert.NotEqual(t, base, digest(kindsBinding("a", "alice", "r1", v1alpha1.SubjectKindUser), kindsBinding("b", "*", "r2")), "kinds")
	assert.NotEqual(t, base, digest(kindsBinding("a", "alice", "r1")), "a binding removed")
	renamed := kindsBinding("c", "alice", "r1")
	renamed.ObjectMeta = metav1.ObjectMeta{Name: "c", Namespace: rbcNamespace}
	assert.NotEqual(t, base, digest(renamed, kindsBinding("b", "*", "r2")), "name")
}

// MatchBindings answers from the table NewRoleProvider compiled at reconcile:
// no request reaches the API server. A client that fails every List once the
// provider is built pins it (#303).
func TestMatchBindings_NoAPICallAfterCompile(t *testing.T) {
	var built atomic.Bool
	var lists atomic.Int32
	base := newRBCClient(t, kindsBinding("exact", "alice", "r1"), kindsBinding("wild", "*", "r2")).(client.WithWatch)
	c := interceptor.NewClient(base,
		interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, l client.ObjectList, opts ...client.ListOption) error {
			if built.Load() {
				lists.Add(1)
				return errors.New("no API call after compile")
			}
			return c.List(ctx, l, opts...)
		}})
	sp, err := NewRoleProvider(context.Background(), c, rbcFocalHost, rbcNamespace, nil)
	require.NoError(t, err)
	built.Store(true)

	assert.Equal(t, []string{"exact", "wild"}, matchedNames(sp.MatchBindings("alice", v1alpha1.SubjectKindUser)))
	assert.NotEmpty(t, sp.BindingsDigest())
	assert.Zero(t, lists.Load())
}
