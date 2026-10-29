package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ErrSubjectNamesClient is returned when a user identity's sub or role-binding
// key names a client. See kdex-tech/host-manager#243.
var ErrSubjectNamesClient = errors.New("subject names a client")

// NamesClient reports whether key names a client: an id in the client
// registry (every client this host has ever had configured, so a removed
// client's credentials never classify as a user; #255), or any key carrying
// the reserved dcr_ prefix of a dynamically registered one, so the check
// never waits on the DCR store.
//
// The configuration is not consulted separately: NewExchanger merges every
// configured id into the registry it builds, so the registry covers them.
// An Exchanger not built by NewExchanger (a test's literal) has no registry,
// and names no client but by the dcr_ prefix.
func (e *Exchanger) NamesClient(key string) bool {
	if e == nil || key == "" {
		return false
	}
	if _, ok := e.clientRegistry[key]; ok {
		return true
	}
	return strings.HasPrefix(key, dcr.ClientIDPrefix)
}

// SubjectKindOf classifies sub when nothing better is known about its kind:
// SubjectKindClient if it names a client (NamesClient), else SubjectKindUser.
// It is sound because #243 refuses every user identity named like a client. A
// future ServiceAccount kind slots in here as one more branch, ahead of the
// User default. See kdex-tech/host-manager#255.
func (e *Exchanger) SubjectKindOf(sub string) kdexv1alpha1.SubjectKind {
	if e.NamesClient(sub) {
		return kdexv1alpha1.SubjectKindClient
	}
	return kdexv1alpha1.SubjectKindUser
}

// kindOrLegacy is the kind of a credential's subject, given the kind the
// credential recorded when it was issued: that kind, carried even when this
// release does not know it. A kind this release does not know, such as a
// future ServiceAccount, then matches only the bindings without
// subjectKinds, never one narrowed to a kind, which is the safe answer for a
// kind this host cannot enforce. Reclassifying it from the sub would hand it
// a [User] binding.
//
// LEGACY(#268): a credential issued before credentials recorded their kind
// records none, and falls back to the kind of its sub (SubjectKindOf). This
// is the one place that fallback is written; #268 removes it.
func (e *Exchanger) kindOrLegacy(recorded kdexv1alpha1.SubjectKind, sub string) kdexv1alpha1.SubjectKind {
	if recorded != "" {
		return recorded
	}
	return e.SubjectKindOf(sub) // LEGACY(#268)
}

// ContextSubjectKind is the kind of the subject of the credential behind ac:
// the kind the credential carries (ClaimSubjectKind), recorded when it was
// issued (kindOrLegacy). It is the one place a context's kind is read, so
// enforcement, a self-mint and whoami agree on it.
//
// LEGACY(#268): a kind-less client_credentials token is a Client, its
// subject the client even after the client is removed, before the sub's
// fallback is consulted.
func (e *Exchanger) ContextSubjectKind(ac AuthContext) kdexv1alpha1.SubjectKind {
	kind, _ := ac[ClaimSubjectKind].(string)
	if kind == "" {
		if _, ok := ac.ClientCredentialsSubject(); ok { // LEGACY(#268)
			return kdexv1alpha1.SubjectKindClient
		}
	}
	sub, _ := ac["sub"].(string)
	return e.kindOrLegacy(kdexv1alpha1.SubjectKind(kind), sub)
}

// patSubjectKind is the kind of a validated PAT's subject: the kind it
// records, through kindOrLegacy.
func (e *Exchanger) patSubjectKind(data *apitoken.TokenData) kdexv1alpha1.SubjectKind {
	return e.kindOrLegacy(data.SubjectKind, data.Subject)
}

// PATAuthContext builds the auth context of a validated API token: its
// subject, the roles and entitlements its KDexRoleBindings grant it under
// site, its static scope (scp), its issue time and its kind, plus the
// subject's data-driven backend claims, which never overwrite those nor set a
// reservedMintClaim. The host PAT middleware and the proxy PAT bridge both
// build their identity here and add only what differs: the middleware's
// claimMappings enrichment, the bridge's PATBridgeClaim.
//
// The kind is the one the PAT records (patSubjectKind), computed once and
// used for both the veto and the resolution.
//
// A PAT the veto refuses (VetoCredential) is refused before anything is
// resolved, with ErrCredentialKindRefused; the refusal is logged by the
// veto, so a caller answers it as an invalid PAT and logs nothing more. This
// is the veto for both PAT paths.
//
// The resolution's role-binding line, and a refusal's line, are written
// under site.
func (e *Exchanger) PATAuthContext(data *apitoken.TokenData, site string) (AuthContext, error) {
	kind := e.patSubjectKind(data)
	if err := e.VetoCredential(data.Subject, kind, data.IssuedAt, site); err != nil {
		return nil, err
	}
	roles, ents, err := e.ResolveInternalRolesAndEntitlements(BindingSubject{Key: data.Subject, Kind: kind, Site: site})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve the roles of an api token's subject: %w", err)
	}
	ac := AuthContext{
		"sub":          data.Subject,
		"roles":        roles,
		"entitlements": ents,
		// The token's static scope rides along under its own key; the
		// structured entitlements above are the authoritative authz model.
		"scp":            data.Scope,
		ClaimIssuedAt:    float64(data.IssuedAt),
		ClaimSubjectKind: string(kind),
	}
	// Resolved fresh, so a backend grant made since the PAT was minted
	// applies (#138).
	mergeBackendClaims(jwt.MapClaims(ac), e.ResolveSubjectClaims(data.Subject))
	return ac, nil
}

// ErrCredentialKindRefused is returned for a credential the veto refuses.
// See VetoCredential.
var ErrCredentialKindRefused = errors.New("credential kind refused by current config")

// errNoVetoRule marks the refusal of a kind this release knows but the veto
// has no rule for: a kind added to the enum without its rule fails closed.
var errNoVetoRule = errors.New("a known kind the veto has no rule for")

// vetoLog writes the veto's refusals. Mirrors bindingKeyLog so it needs no ctx.
var vetoLog = logf.Log.WithName("subject-kind-veto")

// vetoRule is the veto's rule for one kind: it refuses a credential of that
// kind for sub, issued at iat (unix seconds, 0 when unknown), with
// ErrCredentialKindRefused.
type vetoRule func(e *Exchanger, sub string, iat int64) error

// vetoRules holds the rule of every kind the veto enforces. Every kind
// kdexv1alpha1.SubjectKinds lists has one (TestVeto_EveryKnownKindHasARule);
// a known kind without one is refused (errNoVetoRule).
var vetoRules = map[kdexv1alpha1.SubjectKind]vetoRule{
	kdexv1alpha1.SubjectKindClient: (*Exchanger).vetoClient,
	kdexv1alpha1.SubjectKindUser:   (*Exchanger).vetoUser,
}

// VetoCredential is the veto (#255), and its one entry point: current config
// is a veto on a credential's kind, never its source. Every site that
// accepts a credential calls it (or a thin wrapper: VetoPAT, the gate's
// vetoGateCredential) with the credential's sub, its resolved kind
// (ContextSubjectKind, or the kind a PAT records), its issue time and the
// site (the Site* constants). It refuses, with ErrCredentialKindRefused:
//
//   - a Client credential whose sub is not a configured client
//     (IsConfiguredClient), so removing a client stops every live credential
//     it holds, without anyone remembering a revocation step;
//   - a Client credential issued at or before the last time its client was
//     removed (the registry's removedAt), so adding a client back, the normal
//     way to rotate a compromised secret, is a clean slate rather than a
//     revival. A credential with no usable iat (0) is refused whenever its
//     client was ever removed;
//   - a User credential whose sub names a client (NamesClient, which covers
//     the registry): #243's rule, the client keeps the name;
//   - a kind this release knows but has no rule for (errNoVetoRule).
//
// A kind this release does not know passes: it can match only bindings
// without subjectKinds.
//
// A refusal is logged here, at V(1), like every other credential rejection:
// a removed client's retry loop must not flood the log at V(0) (#181). The
// line names the rule, the site and the kind, never the sub, which may be an
// email under RoleBindingClaim (#215); so does the error. The caller answers
// a refusal as it answers an invalid credential, and logs nothing more.
func (e *Exchanger) VetoCredential(sub string, kind kdexv1alpha1.SubjectKind, iat int64, site string) error {
	err := e.vetoSubjectKind(sub, kind, iat)
	if err != nil {
		vetoLog.V(1).Info("refusing a credential whose kind current config contradicts",
			"rule", err.Error(), "site", site, "kind", string(kind))
	}
	return err
}

// vetoSubjectKind applies the rule of kind, without logging.
func (e *Exchanger) vetoSubjectKind(sub string, kind kdexv1alpha1.SubjectKind, iat int64) error {
	if rule, ok := vetoRules[kind]; ok {
		return rule(e, sub, iat)
	}
	if kind.Known() {
		return fmt.Errorf("%w: %w: %q", ErrCredentialKindRefused, errNoVetoRule, kind)
	}
	return nil
}

// vetoClient is the Client rule.
func (e *Exchanger) vetoClient(sub string, iat int64) error {
	if !e.IsConfiguredClient(sub) {
		return fmt.Errorf("%w: a Client credential whose client is not configured", ErrCredentialKindRefused)
	}
	if removedAt := e.clientRemovedAt(sub); removedAt > 0 && iat <= removedAt {
		return fmt.Errorf("%w: a Client credential issued before its client was last removed", ErrCredentialKindRefused)
	}
	return nil
}

// vetoUser is the User rule.
func (e *Exchanger) vetoUser(sub string, _ int64) error {
	if e.NamesClient(sub) {
		return fmt.Errorf("%w: a User credential whose sub names a client", ErrCredentialKindRefused)
	}
	return nil
}

// clientRemovedAt is when the registry last saw id removed from the
// configuration, in unix seconds; 0 when never.
func (e *Exchanger) clientRemovedAt(id string) int64 {
	if e == nil {
		return 0
	}
	return e.clientRegistry[id].RemovedAt
}

// VetoPAT is VetoCredential over a validated PAT: its sub, the kind it
// records (patSubjectKind) and its issue time. /-/apitokens/verify uses it;
// PATAuthContext, which needs the kind itself, calls VetoCredential.
func (e *Exchanger) VetoPAT(data *apitoken.TokenData, site string) error {
	return e.VetoCredential(data.Subject, e.patSubjectKind(data), data.IssuedAt, site)
}

// issuedAtOf is a credential context's issue time in unix seconds, 0 when it
// carries none usable, which the veto refuses wherever the credential's
// client was ever removed.
func issuedAtOf(ac AuthContext) int64 {
	iat, err := ac.GetIssuedAt()
	if err != nil || iat == nil {
		return 0
	}
	return iat.Unix()
}

// clientBindingSubject is the binding subject of an authenticated
// client_credentials client: its id, as a Client.
func clientBindingSubject(id string) BindingSubject {
	return BindingSubject{Key: id, Kind: kdexv1alpha1.SubjectKindClient, Site: SiteClientCredentials}
}

// IsConfiguredClient reports whether id is an operator-configured client: the
// only kind that can authenticate with client_credentials (a dynamically
// registered client is public).
func (e *Exchanger) IsConfiguredClient(id string) bool {
	if e == nil {
		return false
	}
	_, ok := e.config.Clients[id]
	return ok
}

// userBindingSubject resolves the binding subject of a user identity: the
// role-binding key (the RoleBindingClaim, e.g. email, else sub; #189), the
// kind User (#255) and site. It logs the key's resolution under site, at the
// site's role-binding level, and refuses an identity named like a client
// (#243). Every site that issues or re-resolves a user identity goes through
// it, so none can resolve bindings without the guard, or with a kind other
// than User.
func (e *Exchanger) userBindingSubject(claims jwt.MapClaims, sub, site string) (BindingSubject, error) {
	bindingKey := resolveBindingKey(claims, sub, e.config.OIDC.RoleBindingClaim, e.config.OIDC.RequireEmailVerified)
	if log := bindingKeyLog.V(bindingLogLevel(site)); log.Enabled() {
		log.Info("role-binding key resolved", append([]any{"site", site},
			bindingKeyLogKV(claims, sub, bindingKey, e.config.OIDC.RoleBindingClaim, e.config.OIDC.RequireEmailVerified)...)...)
	}
	bs := BindingSubject{Key: bindingKey, Kind: kdexv1alpha1.SubjectKindUser, Site: site}
	return bs, e.refuseClientNamedIdentity(sub, bindingKey)
}

// refuseClientNamedIdentity refuses a user identity whose sub or role-binding
// key names a client (NamesClient). KDexRoleBinding.subject is one namespace
// shared by users and clients, so such a user would inherit every binding
// written for the client. It runs wherever a user identity is issued or
// re-resolved, so on a collision the client keeps its name and the user is
// refused, whichever was created first. Exact names only: a /regex/ or `*`
// binding matches users and clients alike, by design of the matcher, unless
// the binding sets subjectKinds (#255). See kdex-tech/host-manager#243.
func (e *Exchanger) refuseClientNamedIdentity(keys ...string) error {
	for _, key := range keys {
		if e.NamesClient(key) {
			return fmt.Errorf("%w: %q; rename the user or the client", ErrSubjectNamesClient, key)
		}
	}
	return nil
}
