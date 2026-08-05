package sign_test

import (
	"crypto"
	"maps"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSigner returns a Signer wired to a freshly-loaded ECDSA P-256 key.
// Shared across the Project/SignProjected tests so each test focuses on
// behavior rather than key-loading mechanics.
func testSigner(t *testing.T) *sign.Signer {
	t.Helper()
	kp, err := keys.LoadKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
KID: kdex-dev-1769451504

MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXufwXet+BRiqMQDn
7lWcoIgz6AVTAKOOJXlOz8JfxR2hRANCAASq6yLdpv9BkUW8SumvAkl+13QaAFDY
L51w6mkJ5U6GWpH1eZsXgKm0ZZJKEPsN9wYKe2LXT/WPpa5AwGzo7BLm
-----END PRIVATE KEY-----`))
	require.NoError(t, err)
	s, err := sign.NewSigner("aud-test", time.Minute, "iss-test", &kp.Private, "kid-test", &dmapper.Mapper{})
	require.NoError(t, err)
	return s
}

// testSignerWithMapper returns a Signer wired to the shared test key plus a real
// dmapper built from rules — used by confinement tests that must exercise the
// mapper running inside Project.
func testSignerWithMapper(t *testing.T, rules []dmapper.MappingRule) *sign.Signer {
	t.Helper()
	kp, err := keys.LoadKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
KID: kdex-dev-1769451504

MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXufwXet+BRiqMQDn
7lWcoIgz6AVTAKOOJXlOz8JfxR2hRANCAASq6yLdpv9BkUW8SumvAkl+13QaAFDY
L51w6mkJ5U6GWpH1eZsXgKm0ZZJKEPsN9wYKe2LXT/WPpa5AwGzo7BLm
-----END PRIVATE KEY-----`))
	require.NoError(t, err)
	mapper, err := dmapper.NewMapper(rules)
	require.NoError(t, err)
	s, err := sign.NewSigner("aud-test", time.Minute, "iss-test", &kp.Private, "kid-test", mapper)
	require.NoError(t, err)
	return s
}

func TestNewSigner(t *testing.T) {
	tests := []struct {
		name       string
		audience   string
		duration   time.Duration
		issuer     string
		kid        string
		privateKey *crypto.Signer
		mapper     *dmapper.Mapper
		assertions func(*testing.T, *sign.Signer, error)
	}{
		{
			name:     "success",
			audience: "test",
			duration: time.Hour,
			issuer:   "test",
			kid:      "test",
			privateKey: func() *crypto.Signer {
				kp, err := keys.LoadKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
KID: kdex-dev-1769451504

MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXufwXet+BRiqMQDn
7lWcoIgz6AVTAKOOJXlOz8JfxR2hRANCAASq6yLdpv9BkUW8SumvAkl+13QaAFDY
L51w6mkJ5U6GWpH1eZsXgKm0ZZJKEPsN9wYKe2LXT/WPpa5AwGzo7BLm
-----END PRIVATE KEY-----`))
				if err != nil {
					t.Fatal(err)
				}
				return &kp.Private
			}(),
			mapper: &dmapper.Mapper{},
			assertions: func(t *testing.T, s *sign.Signer, err error) {
				assert.NotNil(t, s)
				assert.Nil(t, err)
			},
		},
		{
			name: "missing audience",
			assertions: func(t *testing.T, s *sign.Signer, err error) {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "audience")
			},
		},
		{
			name:     "missing duration",
			audience: "test",
			duration: 0,
			assertions: func(t *testing.T, s *sign.Signer, err error) {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "duration")
			},
		},
		{
			name:     "missing issuer",
			audience: "test",
			duration: time.Hour,
			assertions: func(t *testing.T, s *sign.Signer, err error) {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "issuer")
			},
		},
		{
			name:     "missing kid",
			audience: "test",
			duration: time.Hour,
			issuer:   "test",
			privateKey: func() *crypto.Signer {
				kp, err := keys.LoadKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
KID: kdex-dev-1769451504

MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXufwXet+BRiqMQDn
7lWcoIgz6AVTAKOOJXlOz8JfxR2hRANCAASq6yLdpv9BkUW8SumvAkl+13QaAFDY
L51w6mkJ5U6GWpH1eZsXgKm0ZZJKEPsN9wYKe2LXT/WPpa5AwGzo7BLm
-----END PRIVATE KEY-----`))
				if err != nil {
					t.Fatal(err)
				}
				return &kp.Private
			}(),
			assertions: func(t *testing.T, s *sign.Signer, err error) {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "key id")
			},
		},
		{
			name:       "missing private key",
			audience:   "test",
			duration:   time.Hour,
			issuer:     "test",
			kid:        "test",
			privateKey: nil,
			assertions: func(t *testing.T, s *sign.Signer, err error) {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "private key")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := sign.NewSigner(tt.audience, tt.duration, tt.issuer, tt.privateKey, tt.kid, tt.mapper)
			tt.assertions(t, got, gotErr)
		})
	}
}

func TestSigner_Project_DeterministicAcrossCalls(t *testing.T) {
	s := testSigner(t)
	in := jwt.MapClaims{
		"sub":          "user-42",
		"email":        "user@example.com",
		"entitlements": []string{"pages:/:read"},
		"roles":        []string{"reader"},
		"given_name":   "Test",
		// Volatile noise that the proxy currently splices in — Project must
		// ignore it for the result to be useful as a cache key.
		"headers": map[string]any{"Traceparent": "00-a-b-01"},
		"cookies": map[string]any{"auth_token": "abc"},
	}

	p1, err1 := s.Project(in)
	p2, err2 := s.Project(in)

	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.Equal(t, p1, p2, "Project must be deterministic for the same input")

	// Required registered claims and the plucked set are present; iat/exp/jti
	// must NOT be — those are what SignProjected adds at sign time.
	assert.Equal(t, "user-42", p1["sub"])
	assert.Equal(t, "iss-test", p1["iss"])
	assert.Equal(t, []string{"aud-test"}, p1["aud"])
	assert.Equal(t, "user@example.com", p1["email"])
	assert.Equal(t, []string{"pages:/:read"}, p1["entitlements"])
	assert.Equal(t, "Test", p1["given_name"])
	assert.NotContains(t, p1, "iat")
	assert.NotContains(t, p1, "exp")
	assert.NotContains(t, p1, "jti")
	// Volatile inputs must not leak into the projection.
	assert.NotContains(t, p1, "headers")
	assert.NotContains(t, p1, "cookies")
}

func TestSigner_Project_IgnoresVolatileHeaders(t *testing.T) {
	s := testSigner(t)
	base := jwt.MapClaims{
		"sub":          "user-42",
		"entitlements": []string{"pages:/:read"},
	}
	withTrace1 := jwt.MapClaims{
		"sub":          "user-42",
		"entitlements": []string{"pages:/:read"},
		"headers":      map[string]any{"Traceparent": "00-aaa-bbb-01", "X-Request-Id": "req-1"},
	}
	withTrace2 := jwt.MapClaims{
		"sub":          "user-42",
		"entitlements": []string{"pages:/:read"},
		"headers":      map[string]any{"Traceparent": "00-ccc-ddd-01", "X-Request-Id": "req-2"},
	}

	p0, err := s.Project(base)
	require.NoError(t, err)
	p1, err := s.Project(withTrace1)
	require.NoError(t, err)
	p2, err := s.Project(withTrace2)
	require.NoError(t, err)

	assert.Equal(t, p0, p1)
	assert.Equal(t, p0, p2)
}

func TestSigner_Project_EntitlementChangeChangesProjection(t *testing.T) {
	s := testSigner(t)
	a := jwt.MapClaims{"sub": "user-42", "entitlements": []string{"pages:/:read"}}
	b := jwt.MapClaims{"sub": "user-42", "entitlements": []string{"pages:/:read", "users:me:read"}}

	pa, err := s.Project(a)
	require.NoError(t, err)
	pb, err := s.Project(b)
	require.NoError(t, err)

	assert.NotEqual(t, pa, pb, "an entitlement change MUST change the projection so the cache key invalidates")
}

func TestSigner_SignProjected_AttachesPerTokenIdentifiers(t *testing.T) {
	s := testSigner(t)
	projected := jwt.MapClaims{
		"sub": "user-42",
		"iss": "iss-test",
		"aud": []string{"aud-test"},
	}

	tok1, err := s.SignProjected(projected)
	require.NoError(t, err)
	// Brief sleep so iat shifts at second resolution between the two calls.
	time.Sleep(1100 * time.Millisecond)
	tok2, err := s.SignProjected(projected)
	require.NoError(t, err)

	assert.NotEqual(t, tok1, tok2, "two SignProjected calls with the same projection must differ (iat/jti vary)")

	// The original projection map must not have been mutated (SignProjected
	// copies into a fresh map before adding iat/exp/jti).
	assert.NotContains(t, projected, "iat")
	assert.NotContains(t, projected, "exp")
	assert.NotContains(t, projected, "jti")
}

func TestSigner_SignProjected_IncludesAllProjectedClaims(t *testing.T) {
	s := testSigner(t)
	projected := jwt.MapClaims{
		"sub":          "user-42",
		"iss":          "iss-test",
		"aud":          []string{"aud-test"},
		"entitlements": []string{"pages:/:read"},
		"given_name":   "Test",
	}

	tok, err := s.SignProjected(projected)
	require.NoError(t, err)

	parsed, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(tok, jwt.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	assert.Equal(t, "user-42", claims["sub"])
	assert.Equal(t, "iss-test", claims["iss"])
	// JSON round-trip turns []string -> []any; assert content not type.
	assert.Equal(t, []any{"aud-test"}, claims["aud"])
	assert.Equal(t, []any{"pages:/:read"}, claims["entitlements"])
	assert.Equal(t, "Test", claims["given_name"])
	assert.Contains(t, claims, "iat")
	assert.Contains(t, claims, "exp")
	assert.Contains(t, claims, "jti")
}

func TestSigner_Sign_StillWorksAsWrapper(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Sign(jwt.MapClaims{
		"sub":          "user-42",
		"entitlements": []string{"pages:/:read"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tok)
}

func TestSigner_Duration(t *testing.T) {
	s := testSigner(t)
	assert.Equal(t, time.Minute, s.Duration())
}

// Regression: the original Sign emitted mapper output last via maps.Copy
// so mapper rules could override iat/exp/jti. The auth-config tests rely
// on this to synthesize expired tokens (exp=-1 via a ClaimMappings rule).
// SignProjected must preserve that semantic — projection values override
// the defaults written by SignProjected.
func TestSigner_SignProjected_ProjectionOverridesDefaultExp(t *testing.T) {
	s := testSigner(t)
	projected := jwt.MapClaims{
		"sub": "user-42",
		"iss": "iss-test",
		"aud": []string{"aud-test"},
		"exp": float64(-1), // jwt-go round-trips JSON numbers as float64
	}

	tok, err := s.SignProjected(projected)
	require.NoError(t, err)

	parsed, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(tok, jwt.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	assert.Equal(t, float64(-1), claims["exp"],
		"projection.exp MUST override the default exp set by SignProjected — auth "+
			"tests synthesize expired tokens by injecting exp=-1 through a ClaimMappings rule")
}

// TestSigner_Project_DeduplicatesEntitlements pins that the entitlements claim
// is deduplicated (first-occurrence order preserved) before signing — role
// flattening and the claimMappings concat routinely produce duplicates. See #138.
func TestSigner_Project_DeduplicatesEntitlements(t *testing.T) {
	s := testSigner(t)
	p, err := s.Project(jwt.MapClaims{
		"sub":          "alice",
		"entitlements": []string{"pages::read", "functions::read", "pages::read", "vector_stores:system:read", "vector_stores:system:read"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"pages::read", "functions::read", "vector_stores:system:read"}, p["entitlements"])
}

// TestSigner_Project_CompactsDominatedEntitlements pins that Project reduces the
// entitlements claim with entitlements.Compact (lossless, Dominates-defined) —
// a strictly dominated grant (pages:home:read under pages:*:read) is dropped,
// which the old exact-dup dedup left in place. First-seen order preserved.
// See kdex-tech/host-manager#140.
func TestSigner_Project_CompactsDominatedEntitlements(t *testing.T) {
	s := testSigner(t)
	p, err := s.Project(jwt.MapClaims{
		"sub":          "alice",
		"entitlements": []string{"pages:*:read", "pages:home:read", "functions::read"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"pages:*:read", "functions::read"}, p["entitlements"])
}

// TestSigner_SignScoped_ConfinesScopeControlledClaims pins that SignScoped
// strips scope-controlled claim families absent from grantedScopes AFTER the
// mapper runs. The mapper here injects into entitlements from an arbitrary,
// NON-extra_grants source claim (custom_grants) — proving confinement is
// generic over any ClaimMappings effect, not coupled to a known source claim.
// See kdex-tech/host-manager#140.
func TestSigner_SignScoped_ConfinesScopeControlledClaims(t *testing.T) {
	s := testSignerWithMapper(t, []dmapper.MappingRule{{
		SourceExpression: `(has(self.entitlements) ? self.entitlements : []) + (has(self.custom_grants) ? self.custom_grants : [])`,
		TargetPropPath:   "entitlements",
	}})

	base := jwt.MapClaims{
		"sub":           "alice",
		"email":         "alice@example.com",
		"name":          "Alice",
		"roles":         []string{"admin"},
		"entitlements":  []any{"functions::read"},
		"custom_grants": []any{"resource:ra:all"},
	}

	tests := []struct {
		name          string
		grantedScopes []string
		present       map[string]bool // claim -> expected present in signed token
	}{
		{"entitlements denied strips mapper-injected grant", []string{"openid"},
			map[string]bool{"entitlements": false, "email": false, "roles": false, "name": false}},
		{"entitlements granted keeps grant", []string{"openid", "entitlements"},
			map[string]bool{"entitlements": true}},
		{"email+roles granted, entitlements denied", []string{"email", "roles"},
			map[string]bool{"email": true, "roles": true, "entitlements": false}},
		{"profile granted keeps name", []string{"profile"},
			map[string]bool{"name": true, "entitlements": false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := maps.Clone(base)
			tok, err := s.SignScoped(c, tt.grantedScopes)
			require.NoError(t, err)
			parsed, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(tok, jwt.MapClaims{})
			require.NoError(t, err)
			claims := parsed.Claims.(jwt.MapClaims)
			for claim, want := range tt.present {
				_, got := claims[claim]
				assert.Equalf(t, want, got, "claim %q present=%v want=%v", claim, got, want)
			}
		})
	}
}

// TestSigner_Project_DeduplicatesAfterMapperMerge pins dedup on the PRODUCTION
// path: the extra_grants->entitlements claimMapping concat can reintroduce a
// grant already present in the role set; the result must still be deduped. Also
// verifies the []any / CEL mapper-output shape is handled.
func TestSigner_Project_DeduplicatesAfterMapperMerge(t *testing.T) {
	kp, err := keys.LoadKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
KID: kdex-dev-1769451504

MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXufwXet+BRiqMQDn
7lWcoIgz6AVTAKOOJXlOz8JfxR2hRANCAASq6yLdpv9BkUW8SumvAkl+13QaAFDY
L51w6mkJ5U6GWpH1eZsXgKm0ZZJKEPsN9wYKe2LXT/WPpa5AwGzo7BLm
-----END PRIVATE KEY-----`))
	require.NoError(t, err)
	mapper, err := dmapper.NewMapper([]dmapper.MappingRule{{
		SourceExpression: `(has(self.entitlements) ? self.entitlements : []) + (has(self.extra_grants) ? self.extra_grants : [])`,
		TargetPropPath:   "entitlements",
	}})
	require.NoError(t, err)
	s, err := sign.NewSigner("aud-test", time.Minute, "iss-test", &kp.Private, "kid-test", mapper)
	require.NoError(t, err)

	p, err := s.Project(jwt.MapClaims{
		"sub":          "alice",
		"entitlements": []any{"resource:ra:all", "functions::read"},
		"extra_grants": []any{"resource:ra:all", "resource:rb:read"}, // resource:ra:all duplicates a role grant
	})
	require.NoError(t, err)

	// Flatten to strings regardless of []any/[]string and assert no dup + all present.
	got := map[string]int{}
	switch list := p["entitlements"].(type) {
	case []any:
		for _, e := range list {
			got[e.(string)]++
		}
	case []string:
		for _, e := range list {
			got[e]++
		}
	default:
		t.Fatalf("unexpected entitlements type %T", p["entitlements"])
	}
	assert.Equal(t, 1, got["resource:ra:all"], "the grant present in BOTH role and enrichment sets must appear once")
	assert.Equal(t, 1, got["functions::read"])
	assert.Equal(t, 1, got["resource:rb:read"])
}
