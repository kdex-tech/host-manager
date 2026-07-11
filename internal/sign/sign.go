package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"maps"
	"runtime/debug"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	entitlements "github.com/kdex-tech/entitlements/go"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// signerLog is a dedicated logger for token-mint diagnostics, independently
// controllable via --named-log-level=signer=<N>. Every JWT this package issues
// (FAT, session/access, mint_token) flows through SignProjected, so raising it
// surfaces exactly what claims went into every minted token.
var signerLog = logf.Log.WithName("signer")

type Signer struct {
	audience   string
	duration   time.Duration
	issuer     string
	privateKey *crypto.Signer
	kid        string
	mapper     *dmapper.Mapper
}

// NewSigner creates a new signer.
func NewSigner(
	audience string,
	duration time.Duration,
	issuer string,
	privateKey *crypto.Signer,
	kid string,
	mapper *dmapper.Mapper,
) (*Signer, error) {
	if audience == "" {
		return nil, fmt.Errorf("signer requires an audience")
	}
	if duration == 0 {
		return nil, fmt.Errorf("signer requires a duration")
	}
	if issuer == "" {
		return nil, fmt.Errorf("signer requires an issuer")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("signer requires a private key")
	}
	if kid == "" {
		return nil, fmt.Errorf("signer requires a key id")
	}
	return &Signer{
		audience:   audience,
		duration:   duration,
		issuer:     issuer,
		privateKey: privateKey,
		kid:        kid,
		mapper:     mapper,
	}, nil
}

// profileClaims is the OIDC profile-scope allow-list copied through from
// signingContext to the signed token.
var profileClaims = []string{
	"birthdate",
	"family_name",
	"gender",
	"given_name",
	"locale",
	"middle_name",
	"name",
	"nickname",
	"picture",
	"preferred_username",
	"profile",
	"updated_at",
	"website",
	"zoneinfo",
}

// Project derives the deterministic claim set that will be signed for a
// given signingContext. iat/exp/jti are deliberately omitted: they identify
// the token, not the identity, and putting them in the projection defeats
// the caller's ability to use the projection as a cache key.
//
// The signer's audience is the AUTHORITATIVE outbound aud: Project is
// always called to re-issue a token for a SPECIFIC downstream target (the
// per-function FAT path in proxy.go), and re-using the inbound aud would
// make the issued token transferable to a different audience than the
// signer was configured for. Concretely: a user logs in at the host
// (aud=["https://<host>"]) and then calls a function; proxy.go builds a
// signer with audience=fn.Status.URL, but the previous logic reused the
// inbound host aud, so the function rejected the FAT with "token has
// invalid audience". Always use s.audience.
func (s *Signer) Project(signingContext jwt.MapClaims) (jwt.MapClaims, error) {
	sub, err := signingContext.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("failed to get subject from claims: %w", err)
	}

	projected := jwt.MapClaims{
		"sub": sub,
		"iss": s.issuer,
		"aud": []string{s.audience},
	}

	// custom claims
	// "scp" carries the static scope of a PASETO API token bridged into the
	// authContext by the proxy so the FAT preserves it alongside the
	// structured entitlements. See kdex-tech/host-manager#103.
	for _, claim := range []string{"email", "entitlements", "idp", "roles", "scope", "scp", "grant_type"} {
		if val, ok := signingContext[claim]; ok {
			projected[claim] = val
		}
	}

	// profile claims
	for _, claim := range profileClaims {
		if val, ok := signingContext[claim]; ok {
			projected[claim] = val
		}
	}

	if s.mapper != nil {
		extra, err := s.mapper.Execute(signingContext)
		if err != nil {
			return nil, fmt.Errorf("failed to map claims: %w", err)
		}

		maps.Copy(projected, extra)
	}

	// Compact the entitlements claim before it is signed. Role flattening (a
	// subject bound to several roles that share grants) and the claimMappings
	// concat routinely produce duplicates AND dominated redundancy (e.g.
	// pages:home:read alongside pages:*:read). entitlements.Compact is a
	// lossless, Dominates-defined reduction: it drops strictly-dominated and
	// equivalent-form entries so every minted token carries a minimal set that
	// grants identical authority, and — being defined purely via Dominates — its
	// notion of "broader than" can never drift from attenuation. See
	// kdex-tech/host-manager#138, #140.
	if ent, ok := projected["entitlements"]; ok {
		projected["entitlements"] = compactEntitlements(ent)
	}

	return projected, nil
}

// compactEntitlements losslessly reduces the entitlements claim via
// entitlements.Compact (drop strictly-dominated + equivalent-form entries,
// preserving original strings and first-seen order). It handles the two shapes
// the claim takes — []string (role flattening) and []any (JSON round-trip / CEL
// mapper output) — preserving the shape it was given, and returns v unchanged
// for any other type or if a []any carries a non-string element (malformed).
func compactEntitlements(v any) any {
	switch list := v.(type) {
	case []string:
		return entitlements.Compact(list)
	case []any:
		strs := make([]string, 0, len(list))
		for _, e := range list {
			s, ok := e.(string)
			if !ok {
				return v // malformed (non-string entitlement); leave untouched
			}
			strs = append(strs, s)
		}
		compacted := entitlements.Compact(strs)
		out := make([]any, len(compacted))
		for i, s := range compacted {
			out[i] = s
		}
		return out
	default:
		return v
	}
}

// SignProjected attaches the per-token identifiers (iat/exp/jti) to an
// already-projected claim set and signs it. Use this in tandem with
// Project when caching to skip the projection step on a cache hit.
//
// The projection has the LAST WORD on every field — including iat/exp/jti.
// The original Sign emitted mapper output last via maps.Copy, and several
// call sites depend on that semantic (e.g. dev-mode tests that inject
// exp=-1 via a ClaimMappings rule to synthesize an expired token). Default
// iat/exp/jti are written first, then maps.Copy(outboundClaims, projected)
// overrides anything the projection already carries.
func (s *Signer) SignProjected(projected jwt.MapClaims) (string, error) {
	outboundClaims := make(jwt.MapClaims, len(projected)+3)
	outboundClaims["exp"] = time.Now().Add(s.duration).Unix()
	outboundClaims["iat"] = time.Now().Unix()
	outboundClaims["jti"] = rand.Text()
	maps.Copy(outboundClaims, projected)

	var method jwt.SigningMethod

	// Check the public key type to decide the signing algorithm
	switch (*s.privateKey).Public().(type) {
	case *rsa.PublicKey:
		method = jwt.SigningMethodRS256
	case *ecdsa.PublicKey:
		method = jwt.SigningMethodES256
	default:
		return "", fmt.Errorf("unsupported signer type")
	}

	token := jwt.NewWithClaims(method, outboundClaims)
	token.Header["alg"] = method.Alg()
	token.Header["kid"] = s.kid
	token.Header["typ"] = "JWT"
	signed, err := token.SignedString(*s.privateKey)
	if err == nil && signerLog.V(2).Enabled() {
		// Diagnostic: dump the FULL claim set signed into EVERY JWT this signer
		// issues (FAT, session/access, mint_token). outboundClaims IS exactly
		// what is signed (aud/sub/iss + entitlements/roles/profile + exp/iat/jti)
		// — ground truth for verifying that resolved grants (e.g. vs_entitlements,
		// kdex-tech/host-manager#138) reach the token. It carries identity/profile
		// claims, so it is gated behind an explicitly-enabled logger:
		// --named-log-level=signer=2. V(3) additionally attaches the goroutine
		// stack so the mint's call path (FAT proxy, login, refresh, mint_token, …)
		// is visible.
		if signerLog.V(3).Enabled() {
			signerLog.V(3).Info("minted token", "claims", outboundClaims, "stack", string(debug.Stack()))
		} else {
			signerLog.V(2).Info("minted token", "claims", outboundClaims)
		}
	}
	return signed, err
}

// Sign is a convenience wrapper that runs Project then SignProjected.
// Direct callers that want to cache should call the two steps separately
// so the cache key reflects the deterministic projection rather than the
// raw inbound context (which routinely includes per-request headers like
// Traceparent that defeat the cache).
func (s *Signer) Sign(signingContext jwt.MapClaims) (string, error) {
	projected, err := s.Project(signingContext)
	if err != nil {
		return "", err
	}
	return s.SignProjected(projected)
}

// SignScoped is Sign with OAuth scope confinement: it projects the context
// (which runs the ClaimMappings mapper and Compact), removes the scope-controlled
// claim families absent from grantedScopes, then signs. Confinement runs AFTER
// the mapper, so a ClaimMappings rule that injects into a scope-controlled family
// cannot smuggle it into a token whose scope did not grant it — regardless of
// which source claim the rule reads. Used by the primary subject mints
// (LoginLocal, mintTokensFromCode, mintTokensFromSubject); FAT projection,
// mint_token, OIDC exchange, and client_credentials keep raw Sign/Project.
// See kdex-tech/host-manager#140.
func (s *Signer) SignScoped(signingContext jwt.MapClaims, grantedScopes []string) (string, error) {
	projected, err := s.Project(signingContext)
	if err != nil {
		return "", err
	}
	confineByScope(projected, grantedScopes)
	return s.SignProjected(projected)
}

// confineByScope deletes the OAuth scope-controlled claim families not present
// in grantedScopes. It governs only the standard families — email, profile
// (profileClaims), entitlements, roles. The openid scope controls id_token
// issuance, not a claim here; any non-standard claim the mapper produced passes
// through untouched. Deleting an absent claim is a no-op.
func confineByScope(projected jwt.MapClaims, grantedScopes []string) {
	granted := func(scope string) bool { return slices.Contains(grantedScopes, scope) }
	if !granted("email") {
		delete(projected, "email")
	}
	if !granted("profile") {
		for _, claim := range profileClaims {
			delete(projected, claim)
		}
	}
	if !granted("entitlements") {
		delete(projected, "entitlements")
	}
	if !granted("roles") {
		delete(projected, "roles")
	}
}

// Duration returns the lifetime each signed token is valid for. Cache
// implementations should subtract a skew from this to ensure a cached
// token always has meaningful remaining life on hit.
func (s *Signer) Duration() time.Duration { return s.duration }
