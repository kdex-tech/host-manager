package apitoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/sign"
	corev1 "k8s.io/api/core/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// apitokenLog is the fallback logger for the mint path, which takes no
// context to carry a request-scoped one. ValidateToken has a context and uses
// logf.FromContext so its rejections correlate with the request that carried
// the token.
var apitokenLog = logf.Log.WithName("apitoken")

var (
	instance *KeyPairs
	once     sync.Once
)

// pasetoV4PublicHeader is the fixed protocol header of every v4.public PASETO
// token produced by V4Sign. In white-label (replace) prefixing this header is
// swapped out for the host's brand prefix on the wire and restored before any
// parse, so the bytes handed to the parser are identical to what V4Sign
// produced and the signature is unaffected.
const pasetoV4PublicHeader = "v4.public."

// RevocationHorizon is how long a revocation lasts on a host with no maximum
// API token lifetime. A revocation must outlive every token it revokes, and it
// only revokes tokens issued up to its own timestamp, so a long one blocks no
// key minted afterwards under the same name.
const RevocationHorizon = 10 * 365 * 24 * time.Hour

// RevocationClass is the cache class revocations live in, in the scope that
// survives host generations: a revocation is state a request created, and
// losing it makes a revoked token valid again. See kdex-tech/host-manager#245.
const RevocationClass = "apitoken-revocation-v2"

// LegacyRevocationClass is the cycled class revocations lived in up to
// v0.27.x, where every host reconfiguration abandoned them. TokenManager still
// reads and writes it (WithLegacyRevocationCache) so that, during a rolling
// upgrade, a replica on v0.27.x and one on v0.28.0 honour each other's
// revocations, and a rollback below v0.28.0 keeps the ones made since.
//
// LEGACY(#259): remove with every LEGACY(#259) site, once every host has run
// v0.28.0 or later and a rollback below it is no longer supported.
const LegacyRevocationClass = "apitoken-revocation"

// RevocationCaches returns the revocation store and the legacy class, created
// with the options every caller must agree on. MaxItems 0 means unbounded:
// the in-memory backend would otherwise evict a revocation to make room,
// which un-revokes a token.
func RevocationCaches(cm cache.CacheManager) (store, legacy cache.Cache) {
	store = cm.GetCache(RevocationClass, cache.CacheOptions{MaxItems: new(0), Uncycled: true})
	legacy = cm.GetCache(LegacyRevocationClass, cache.CacheOptions{}) // LEGACY(#259)
	return store, legacy
}

// subjectRevocationPrefix namespaces subject-wide revocations. A jti is bare
// hex, so no jti can collide with a key carrying it.
const subjectRevocationPrefix = "sub:"

// ErrTTLExceedsMax is returned when a mint asks for a lifetime longer than the
// host's KDexHost.spec.auth.apiToken.maxTTL. See kdex-tech/host-manager#238.
var ErrTTLExceedsMax = errors.New("ttl exceeds the host's maximum API token lifetime")

type TokenData struct {
	Action     string `json:"act"`
	Audience   string `json:"aud"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`
	Issuer     string `json:"iss"`
	JTI        string `json:"jti"`
	KID        string `json:"kid"`
	NotBefore  int64  `json:"nbf"`
	Scope      string `json:"scp"`
	Subject    string `json:"sub"`
}

type KeyPair struct {
	ActiveKey bool
	KeyId     string
	PublicKey *paseto.V4AsymmetricPublicKey
	SecretKey *paseto.V4AsymmetricSecretKey
}

type KeyPairs []*KeyPair

func (p *KeyPairs) ActiveKey() *KeyPair {
	if p == nil {
		return nil
	}
	if len(*p) == 1 {
		return (*p)[0]
	}
	for _, pair := range *p {
		if pair.ActiveKey {
			return pair
		}
	}
	return nil
}

func (p *KeyPairs) GetKey(kid string) (*KeyPair, bool) {
	for _, pair := range *p {
		if pair.KeyId == kid {
			return pair, true
		}
	}
	return nil, false
}

type TokenManager struct {
	activeKey       KeyPair
	issuer          string
	keyPairs        KeyPairs
	maxTTL          time.Duration
	revocationCache cache.Cache
	// legacyRevocationCache is LegacyRevocationClass, nil when not wired.
	// LEGACY(#259).
	legacyRevocationCache cache.Cache
	tokenPrefix           string
}

func APITokenManagerLoader(
	issuer string,
	secrets kdexv1alpha1.Secrets,
	revocationCache cache.Cache,
	devMode bool,
) (*TokenManager, error) {
	filtered := secrets.Filter(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "api-key" })
	if !devMode && len(filtered) == 0 {
		return nil, nil
	}

	// reverse sort by creation timestamp
	slices.SortFunc(filtered, func(a, b corev1.Secret) int {
		// Sort to Ascending - oldest to newest
		return a.CreationTimestamp.Compare(b.CreationTimestamp.Time)
	})

	pairs := &KeyPairs{}
	found := false

	for i, secret := range filtered {
		isActive := false
		if secret.Annotations["kdex.dev/active-key"] == "true" {
			isActive = true
		}

		kp, err := LoadKeysFromSecret(&secret, isActive)
		if err != nil {
			return nil, err
		}

		found = true
		*pairs = append(*pairs, kp)

		// make sure only one key is active
		if kp.ActiveKey && i > 0 {
			(*pairs)[i-1].ActiveKey = false
		}
	}

	if found {
		if len(*pairs) > 1 && pairs.ActiveKey() == nil {
			(*pairs)[len(*pairs)-1].ActiveKey = true
		}

		// If only one key, make it active if not already
		if len(*pairs) == 1 && pairs.ActiveKey() == nil {
			(*pairs)[0].ActiveKey = true
		}

		return NewTokenManager(issuer, pairs, revocationCache)
	}

	if devMode {
		return NewTokenManager(issuer, GenerateDevmodeKeyPair(), revocationCache)
	}

	return nil, nil
}

func NewTokenManager(issuer string, keyPairs *KeyPairs, revocationCache cache.Cache) (*TokenManager, error) {
	return &TokenManager{
		issuer:          issuer,
		activeKey:       *keyPairs.ActiveKey(),
		keyPairs:        *keyPairs,
		revocationCache: revocationCache,
		// tokenPrefix defaults to "" — prefixing is opt-in via WithTokenPrefix.
	}, nil
}

// WithTokenPrefix sets this host's white-label API token prefix. Prefixing is
// off by default (empty), in which case tokens are emitted as bare
// "v4.public." PASETO strings. When set, the prefix REPLACES the PASETO header
// on the wire (see wrap/unwrap). Returns the receiver for chaining. This is the
// single configuration point for the prefix; the controller sources it from
// KDexHost.spec.auth.apiToken.tokenPrefix (falling back to the
// NexusConfiguration default) and calls this once per host.
func (tm *TokenManager) WithTokenPrefix(prefix string) *TokenManager {
	tm.tokenPrefix = prefix
	return tm
}

// TokenPrefix returns this host's white-label API token prefix (empty when
// prefixing is off). Callers that need to discriminate a brand-prefixed PAT on
// the wire (e.g. the Bearer auth path) use this to recognize the prefix without
// reaching into the manager's internals.
func (tm *TokenManager) TokenPrefix() string {
	return tm.tokenPrefix
}

// WithMaxTTL sets the longest lifetime this host mints an API token for; zero
// (the default) leaves mint lifetimes unbounded. The controller sources it from
// KDexHost.spec.auth.apiToken.maxTTL. Returns the receiver for chaining.
func (tm *TokenManager) WithMaxTTL(maxTTL time.Duration) *TokenManager {
	tm.maxTTL = maxTTL
	return tm
}

// WithLegacyRevocationCache also reads and writes per-token revocations in
// LegacyRevocationClass, for the rolling upgrade and rollback it describes.
// Returns the receiver for chaining. LEGACY(#259).
func (tm *TokenManager) WithLegacyRevocationCache(legacy cache.Cache) *TokenManager {
	tm.legacyRevocationCache = legacy
	return tm
}

// MaxTTL returns the host's maximum API token lifetime, zero when unbounded.
func (tm *TokenManager) MaxTTL() time.Duration {
	return tm.maxTTL
}

// RevocationTTL is the shortest lifetime of a revocation: never shorter than
// the longest token this host can mint, so a revoked token cannot come back.
func (tm *TokenManager) RevocationTTL() time.Duration {
	return max(RevocationHorizon, tm.maxTTL)
}

// revoke records that every token carrying jti and issued up to now is
// revoked, for at least RevocationTTL, in the revocation store and in the
// legacy class when one is wired.
func (tm *TokenManager) revoke(ctx context.Context, jti string, ttl time.Duration) error {
	if err := tm.recordRevocation(ctx, tm.revocationCache, jti, ttl); err != nil {
		return err
	}
	if tm.legacyRevocationCache != nil { // LEGACY(#259)
		return tm.recordRevocation(ctx, tm.legacyRevocationCache, jti, ttl)
	}
	return nil
}

// recordRevocation stores now as key's revocation time in store, atomically
// against concurrent revocations. A shorter ttl than RevocationTTL is raised,
// so no caller can shorten a revocation by re-revoking with a small one.
//
// The stored time never moves backwards: a re-revocation on a replica whose
// clock lags keeps the later time, or the tokens issued in between would
// validate again. Replicas are assumed NTP-synced; a token minted on one
// replica within the clock skew of its revocation on another can fall on
// either side of it (kdex-tech/host-manager#250).
func (tm *TokenManager) recordRevocation(ctx context.Context, store cache.Cache, key string, ttl time.Duration) error {
	now := time.Now().UTC()
	_, err := store.Update(ctx, key, func(stored string, found bool) (string, bool) {
		// An entry with no readable time revoked outright; now revokes
		// every token that exists, so it replaces it and lets the key be
		// re-minted afterwards.
		if at, perr := time.Parse(time.RFC3339Nano, stored); found && perr == nil && at.After(now) {
			return stored, true // refresh the ttl, keep the later time
		}
		return now.Format(time.RFC3339Nano), true
	}, cache.WithTTL(max(ttl, tm.RevocationTTL())))
	return err
}

// latestRevocation is the later of two stored revocations of one key. Two
// times compare as times. A value with no readable time was written before
// revocations carried one, so a timed value is the later write: it replaced
// the untimed one when the key was re-revoked (recordRevocation), and
// re-imposing the untimed one would revoke a key legitimately re-minted
// since. Between two untimed values, a is kept.
//
// This assumes nothing that writes untimed values (host-manager v0.25.x or
// earlier) still runs beside a later version: the fleet has been on v0.26.0
// or later since 2026-10-20, and a rollback below v0.26.0 is not supported.
func latestRevocation(a, b string) string {
	at, aerr := time.Parse(time.RFC3339Nano, a)
	bt, berr := time.Parse(time.RFC3339Nano, b)
	switch {
	case aerr != nil:
		if berr != nil {
			return a
		}
		return b
	case berr != nil:
		return a
	case bt.After(at):
		return b
	default:
		return a
	}
}

// CapTTL shortens ttl to the host's maximum. It is for lifetimes the server
// chooses itself; a lifetime a caller asked for is refused, not shortened, so
// the caller is never handed a token that expires sooner than it requested.
func (tm *TokenManager) CapTTL(ttl time.Duration) time.Duration {
	if tm.maxTTL > 0 && ttl > tm.maxTTL {
		return tm.maxTTL
	}
	return ttl
}

// wrap converts a freshly signed token to its on-the-wire form by REPLACING the
// PASETO "v4.public." header with this host's brand prefix (e.g.
// "kdex_pat_<payload>.<footer>"). No-op when no prefix is configured. Must be
// applied only AFTER signing. Because the swap is a deterministic substitution
// of a fixed header for a fixed prefix, unwrap restores the exact original
// bytes, so the signature is unaffected.
func (tm *TokenManager) wrap(signed string) string {
	if tm.tokenPrefix == "" {
		return signed
	}
	return tm.tokenPrefix + strings.TrimPrefix(signed, pasetoV4PublicHeader)
}

// unwrap restores the PASETO header on an inbound token before parsing. It is
// deliberately lenient and ordered so bare tokens are detected first: a token
// that already begins with "v4.public." (e.g. issued before prefixing was
// enabled, or sent by a client that omits the prefix) is returned unchanged;
// otherwise, if it carries this host's prefix, the prefix is swapped back to
// the header. Anything else is passed through untouched (it will fail the
// signature check downstream). Must be applied BEFORE any parse.
func (tm *TokenManager) unwrap(signed string) string {
	if tm.tokenPrefix == "" || strings.HasPrefix(signed, pasetoV4PublicHeader) {
		return signed
	}
	if rest, ok := strings.CutPrefix(signed, tm.tokenPrefix); ok {
		return pasetoV4PublicHeader + rest
	}
	return signed
}

func (tm *TokenManager) KeyPairs() KeyPairs {
	return tm.keyPairs
}

func (tm *TokenManager) RevokeByMetadata(ctx context.Context, aud, sub, act string, ttl time.Duration) error {
	if tm.revocationCache == nil {
		return fmt.Errorf("revocation cache not configured")
	}

	return tm.revoke(ctx, GenerateJTI(aud, sub, act), ttl)
}

// RevokeSubject revokes, as of now, every API token this host issued for
// sub on any audience, whatever its act, so it reaches keys nobody recorded.
// SubjectRevokedSince lets the paths that issue new credentials refuse one
// whose authentication predates it. A token minted afterwards from a fresh
// authentication (a re-signup under the same address) is valid. Like a
// per-token revocation it lasts at least RevocationTTL and never moves back.
//
// It is written only to the revocation store: a replica on v0.27.x or earlier
// cannot read it, so it takes effect host-wide once every replica runs
// v0.28.0, and a rollback below v0.28.0 drops it. See
// kdex-tech/host-manager#257.
func (tm *TokenManager) RevokeSubject(ctx context.Context, sub string, ttl time.Duration) error {
	if tm.revocationCache == nil {
		return fmt.Errorf("revocation cache not configured")
	}

	return tm.recordRevocation(ctx, tm.revocationCache, subjectRevocationKey(sub), ttl)
}

// SubjectRevokedSince reports whether sub was revoked (RevokeSubject) at or
// after issuedAt, i.e. whether a credential for sub authenticated at issuedAt
// is cut off. A store that cannot be read is an error, never a no.
func (tm *TokenManager) SubjectRevokedSince(ctx context.Context, sub string, issuedAt time.Time) (bool, error) {
	if tm.revocationCache == nil {
		return false, nil
	}
	revokedAt, found, _, err := tm.revocationCache.Get(ctx, subjectRevocationKey(sub))
	if err != nil {
		return false, fmt.Errorf("failed to check revocation status: %w", err)
	}
	return found && revokedNoEarlierThan(revokedAt, issuedAt), nil
}

// subjectRevocationKey is the revocation-store key of sub. The store is
// already per host (its cache prefix), so a subject revocation covers every
// audience this host issues tokens for.
func subjectRevocationKey(sub string) string {
	hash := sha256.Sum256([]byte(sub))
	return subjectRevocationPrefix + hex.EncodeToString(hash[:])
}

// AdoptStrandedRevocations merges into the revocation store every revocation
// LegacyRevocationClass holds under any host generation, so the ones host
// reconfigurations stranded are in force again. Each key keeps the later
// (latestRevocation) of what the store has and what any generation holds, atomically
// against concurrent revocations, so nothing moves back in time. It returns
// how many entries it strengthened, and is idempotent and safe to run on
// every replica at once. See kdex-tech/host-manager#245.
//
// LEGACY(#259): remove with LegacyRevocationClass.
func (tm *TokenManager) AdoptStrandedRevocations(ctx context.Context, cm cache.CacheManager) (int, error) {
	if tm.revocationCache == nil {
		return 0, fmt.Errorf("revocation cache not configured")
	}

	stranded := map[string]cache.Entry{}
	err := cm.ScanGenerations(ctx, LegacyRevocationClass, func(e cache.Entry) error {
		if prev, seen := stranded[e.Key]; seen {
			e.Value = latestRevocation(prev.Value, e.Value)
			e.TTL = max(prev.TTL, e.TTL)
		}
		stranded[e.Key] = e
		return nil
	})
	if err != nil {
		return 0, err
	}

	adopted := 0
	for jti, e := range stranded {
		// A plain read first: the dual write keeps the two classes equal
		// for nearly every key, and Update's transaction costs three round
		// trips.
		if current, found, _, err := tm.revocationCache.Get(ctx, jti); err == nil && found && latestRevocation(current, e.Value) == current {
			continue
		}
		ttl := e.TTL
		if ttl <= 0 {
			ttl = tm.RevocationTTL()
		}
		wrote, err := tm.revocationCache.Update(ctx, jti, func(current string, found bool) (string, bool) {
			if !found {
				return e.Value, true
			}
			merged := latestRevocation(current, e.Value)
			return merged, merged != current
		}, cache.WithTTL(ttl))
		if err != nil {
			return adopted, err
		}
		if wrote {
			adopted++
		}
	}
	return adopted, nil
}

func (tm *TokenManager) RevokeToken(ctx context.Context, signed string) error {
	if tm.revocationCache == nil {
		return fmt.Errorf("revocation cache not configured")
	}

	// Strip the application-level prefix (if any) before any PASETO parsing.
	signed = tm.unwrap(signed)

	// 1. Peek at the footer to get the KID
	parser := paseto.NewParser()
	footerBytes, err := parser.UnsafeParseFooter(paseto.V4Public, signed)
	if err != nil {
		return err
	}

	var footerData struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(footerBytes, &footerData); err != nil {
		return err
	}

	// 2. Lookup the public key
	keyPair, exists := tm.keyPairs.GetKey(footerData.KID)
	if !exists {
		return fmt.Errorf("key not found: %s", footerData.KID)
	}

	// 3. Parse the token to get JTI and expiration
	// We don't use tm.ValidateToken because it might perform a revocation check
	// and we want to be able to revoke a token even if it's already revoked (idempotency).
	token, err := parser.ParseV4Public(*keyPair.PublicKey, signed, nil)
	if err != nil {
		return err
	}

	jti, err := token.GetJti()
	if err != nil {
		return err
	}

	exp, err := token.GetExpiration()
	if err != nil {
		return err
	}

	ttl := time.Until(exp)
	if ttl <= 0 {
		// Already expired, no need to revoke in cache
		return nil
	}

	return tm.revoke(ctx, jti, ttl)
}

// revoked reports whether a revocation covers token: one of its jti, in the
// revocation store or the legacy class, or one of its subject. The lookups
// run concurrently, which valkey-go pipelines into about one round trip. A
// store that cannot be read fails the check rather than admitting the token.
func (tm *TokenManager) revoked(ctx context.Context, token *paseto.Token) (bool, error) {
	jti, err := token.GetJti()
	if err != nil {
		return false, err
	}
	sub, err := token.GetSubject()
	if err != nil {
		return false, err
	}

	type lookup struct {
		store cache.Cache
		key   string
	}
	lookups := []lookup{{tm.revocationCache, jti}, {tm.revocationCache, subjectRevocationKey(sub)}}
	if tm.legacyRevocationCache != nil { // LEGACY(#259)
		lookups = append(lookups, lookup{tm.legacyRevocationCache, jti})
	}

	revoked := make([]bool, len(lookups))
	errs := make([]error, len(lookups))
	var wg sync.WaitGroup
	for i, l := range lookups {
		wg.Go(func() {
			revokedAt, found, _, err := l.store.Get(ctx, l.key)
			revoked[i], errs[i] = found && issuedNoLaterThan(token, revokedAt), err
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return false, fmt.Errorf("failed to check revocation status: %w", err)
	}
	return slices.Contains(revoked, true), nil
}

// issuedNoLaterThan reports whether token was issued at or before a revocation stored
// at revokedAt. An entry without a timestamp (written before revocations
// carried one) or a token without an iat revokes outright.
func issuedNoLaterThan(token *paseto.Token, revokedAt string) bool {
	iat, err := token.GetIssuedAt()
	if err != nil {
		return true
	}
	return revokedNoEarlierThan(revokedAt, iat)
}

// revokedNoEarlierThan reports whether a revocation stored at revokedAt
// covers something issued at issuedAt. An entry without a readable time
// revokes outright.
func revokedNoEarlierThan(revokedAt string, issuedAt time.Time) bool {
	at, err := time.Parse(time.RFC3339Nano, revokedAt)
	if err != nil {
		return true
	}
	return !issuedAt.After(at)
}

func (tm *TokenManager) MintStatelessKey(aud string, sub string, action string, scope string, ttl time.Duration) (string, error) {
	// FAIL CLOSED, the PASETO half of the JWT rule in sign.Signer. A PAT is a
	// credential; a credential that names nobody is not a supported
	// configuration. paseto.Token.SetSubject would happily write `sub: ""`,
	// and unlike a MISSING claim (which Token.GetSubject rejects at parse) an
	// EMPTY one survives every rule the parser applies -- so without this the
	// only PASETO shape that can carry an unattributable identity is the one
	// we would have minted ourselves. See sign.ErrSubjectlessCredential.
	if sub == "" {
		apitokenLog.Error(sign.ErrSubjectlessCredential,
			"refusing to mint an API token for a credential that names nobody; "+sign.SubjectlessRemedy,
			"audience", aud, "action", action)
		return "", sign.ErrSubjectlessCredential
	}

	// Every mint path signs here, so the host's maximum holds whichever one
	// computed ttl (host-manager#238).
	if tm.maxTTL > 0 && ttl > tm.maxTTL {
		return "", fmt.Errorf("%w: requested %s, maximum %s", ErrTTLExceedsMax, ttl, tm.maxTTL)
	}

	now := time.Now()
	exp := now.Add(ttl)

	token := paseto.NewToken()

	token.SetAudience(aud)
	token.SetExpiration(exp)
	// iat carries sub-second precision (RFC 3339 allows it; go-paseto's
	// GetTime parses it) where SetIssuedAt would truncate to whole seconds:
	// a revocation revokes the tokens issued up to it, so a key re-minted in
	// the same second as a revocation must be distinguishable from one
	// minted before it.
	//
	// DEPENDENCY workaround. Pinned: aidanwoods.dev/go-paseto v1.6.0, which
	// is also the newest release (checked 2026-10-22: v1.6.0 of
	// 2025-12-27 is @latest, and upstream main at 8653d50 is that tag).
	// Token.SetTime there still formats with time.RFC3339, i.e. whole
	// seconds, so no upgrade fixes this. It is a library choice rather than
	// a defect (its GetTime parses fractional seconds), so the workaround
	// stands: once a release's SetTime keeps sub-second precision, replace
	// this line with token.SetIssuedAt(now).
	token.SetString("iat", now.UTC().Format(time.RFC3339Nano))
	token.SetIssuer(tm.issuer)
	token.SetJti(GenerateJTI(aud, sub, action))
	token.SetNotBefore(now)
	token.SetSubject(sub)

	token.SetString("act", action)
	token.SetString("scp", scope)

	token.SetFooter([]byte(`{"kid":"` + tm.activeKey.KeyId + `"}`))

	signed := token.V4Sign(*tm.activeKey.SecretKey, nil)

	return tm.wrap(signed), nil
}

// ValidateToken parses and verifies a PASETO API token.
//
// expectedAudience is REQUIRED in spirit but technically optional in
// signature:
//   - non-empty: a paseto.ForAudience rule is added so a token minted
//     for a different audience is rejected. This is the correct mode
//     for any handler that uses ValidateToken's success as proof the
//     bearer should be granted access on the receiving party.
//   - empty: the audience check is skipped. This is ONLY appropriate
//     when the token is being INSPECTED (e.g. to extract its subject
//     for a revocation flow) — not when validating for use. Passing
//     "" in any other context is the kdex-tech/host-manager#69
//     confused-deputy regression.
func (tm *TokenManager) ValidateToken(ctx context.Context, signed, expectedAudience string) (*TokenData, error) {
	// Strip the application-level prefix (if any) before any PASETO parsing.
	signed = tm.unwrap(signed)

	// 1. Peek at the footer without verifying the signature
	// This is safe because the footer is always in the clear (Base64)
	parser := paseto.NewParser()
	footerBytes, err := parser.UnsafeParseFooter(paseto.V4Public, signed)
	if err != nil {
		return nil, err
	}

	// 2. Extract the KID from the JSON footer
	var footerData struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(footerBytes, &footerData); err != nil {
		return nil, err
	}

	// 3. Lookup the public key in your local cache
	keyPair, exists := tm.keyPairs.GetKey(footerData.KID)
	if !exists {
		return nil, fmt.Errorf("key not found: %s", footerData.KID)
	}

	parser.AddRule(paseto.IssuedBy(tm.issuer))
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))
	if expectedAudience != "" {
		parser.AddRule(paseto.ForAudience(expectedAudience))
	}

	token, err := parser.ParseV4Public(*keyPair.PublicKey, signed, nil)
	if err != nil {
		return nil, err
	}

	// 4. Revocation check
	if tm.revocationCache != nil {
		revoked, err := tm.revoked(ctx, token)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, fmt.Errorf("token revoked")
		}
	}

	subject, err := token.GetSubject()
	if err != nil {
		return nil, err
	}
	// FAIL CLOSED at the validation end too, symmetric with the mint above and
	// with the JWT check in Config.WithAuthentication. GetSubject already
	// rejects a MISSING `sub`; this rejects a PRESENT-but-empty one, which is
	// what a token minted before the mint-side guard existed carries. Every
	// caller of ValidateToken turns its success into an identity
	// (hostPATIdentity, the proxy's PAT bridge) or into an answer ABOUT an
	// identity (/-/apitokens/verify), so a token that names nobody has to be
	// invalid here rather than anonymous later.
	if subject == "" {
		logf.FromContext(ctx).Error(sign.ErrSubjectlessCredential,
			"rejecting an API token that names nobody; "+sign.SubjectlessRemedy,
			"audience", expectedAudience)
		return nil, sign.ErrSubjectlessCredential
	}

	action, err := token.GetString("act")
	if err != nil {
		return nil, err
	}

	scope, err := token.GetString("scp")
	if err != nil {
		return nil, err
	}

	audience, err := token.GetAudience()
	if err != nil {
		return nil, err
	}

	exp, err := token.GetExpiration()
	if err != nil {
		return nil, err
	}

	iat, err := token.GetIssuedAt()
	if err != nil {
		return nil, err
	}

	issuer, err := token.GetIssuer()
	if err != nil {
		return nil, err
	}

	jti, err := token.GetJti()
	if err != nil {
		return nil, err
	}

	nbf, err := token.GetNotBefore()
	if err != nil {
		return nil, err
	}

	return &TokenData{
		Audience:   audience,
		Expiration: exp.Unix(),
		IssuedAt:   iat.Unix(),
		Issuer:     issuer,
		JTI:        jti,
		KID:        footerData.KID,
		NotBefore:  nbf.Unix(),
		Subject:    subject,
		Action:     action,
		Scope:      scope,
	}, nil
}

func GenerateJTI(aud, sub, act string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", aud, sub, act)))

	return hex.EncodeToString(hash[:])
}

func GenerateKID(pubBytes []byte) string {
	hash := sha256.Sum256(pubBytes)

	return hex.EncodeToString(hash[:])[:16]
}

func GenerateDevmodeKeyPair() *KeyPairs {
	once.Do(func() {
		secretKey := paseto.NewV4AsymmetricSecretKey()

		publicKey := secretKey.Public()
		exportedBytes := publicKey.ExportBytes()

		instance = &KeyPairs{
			{
				ActiveKey: true,
				KeyId:     GenerateKID(exportedBytes),
				PublicKey: &publicKey,
				SecretKey: &secretKey,
			},
		}
	})
	return instance
}

// LoadKeysFromSecret loads an key pair from a Kubernetes Secret.
func LoadKeysFromSecret(secret *corev1.Secret, isActive bool) (*KeyPair, error) {
	privateKeyBytes, ok := secret.Data["private-key"]
	if !ok || len(privateKeyBytes) == 0 {
		return nil, fmt.Errorf("private-key is required")
	}

	secretKey, err := paseto.NewV4AsymmetricSecretKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	publicKey := secretKey.Public()
	exportedBytes := publicKey.ExportBytes()
	publicKeyBytes, ok := secret.Data["public-key"]

	if ok {
		if !bytes.Equal(exportedBytes, publicKeyBytes) {
			return nil, fmt.Errorf("public key %x does not match argument %x", exportedBytes, publicKeyBytes)
		}
	}

	keyPair := &KeyPair{
		KeyId:     GenerateKID(exportedBytes),
		PublicKey: &publicKey,
		SecretKey: &secretKey,
	}

	keyPair.ActiveKey = isActive

	return keyPair, nil
}
