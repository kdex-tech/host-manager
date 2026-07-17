package auth

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// AuthorizationChecker validates whether a user has the required permissions.
type AuthorizationChecker struct {
	ec  *entitlements.EntitlementsChecker
	log logr.Logger
}

// NewAuthorizationChecker creates a new authorization checker.
func NewAuthorizationChecker(anonymousEntitlements []string, log logr.Logger) *AuthorizationChecker {
	return &AuthorizationChecker{
		ec:  entitlements.NewEntitlementsChecker(anonymousEntitlements, "", false).WithLogger(log.WithName("entitlements")),
		log: log,
	}
}

func (ac *AuthorizationChecker) CheckAccess(
	ctx context.Context,
	resource string,
	resourceName string,
	kdexreqs []kdexv1alpha1.SecurityRequirement,
	verbs ...string,
) (bool, error) {
	if resource == "" || resourceName == "" {
		return false, fmt.Errorf("resource and resourceName must not be empty")
	}

	parsedEntitlements := ac.GetParsedEntitlements(ctx)
	requirements := ac.ParseRequirements(kdexreqs)

	ac.log.V(2).Info("CheckAccess", "resource", resource, "resourceName", resourceName)

	return ac.ec.VerifyResourceParsedEntitlements(resource, resourceName, parsedEntitlements, requirements, verbs...)
}

func (ac *AuthorizationChecker) CalculateRequirements(
	resource string,
	resourceName string,
	kdexreqs []kdexv1alpha1.SecurityRequirement,
	verbs ...string,
) ([]kdexv1alpha1.SecurityRequirement, error) {
	if resource == "" || resourceName == "" {
		return nil, fmt.Errorf("resource and resourceName must not be empty")
	}

	requirements := entitlements.Requirements{}
	for _, v := range kdexreqs {
		requirements = append(requirements, v)
	}

	requirements, err := ac.ec.CalculateResourceRequirements(resource, resourceName, requirements, verbs...)
	if err != nil {
		return nil, err
	}

	kreq := make([]kdexv1alpha1.SecurityRequirement, 0, len(requirements))
	for _, v := range requirements {
		kreq = append(kreq, v)
	}

	return kreq, nil
}

func (ac *AuthorizationChecker) GetParsedEntitlements(ctx context.Context) entitlements.ParsedEntitlements {
	authContext, _ := GetAuthContext(ctx)

	userEntitlements := entitlements.Entitlements{}

	contextEntitlements, _ := authContext.GetEntitlements()
	if len(contextEntitlements) > 0 {
		userEntitlements["bearer"] = contextEntitlements

		// PAT-bridge callers (proxy PASETO PAT -> authContext) authenticated
		// via the authorization-code (oauth2) flow: a PAT IS an oauth2
		// authentication, so the SAME role-resolved entitlements must also
		// satisfy operation requirements declared under the "oauth2" scheme
		// (e.g. {oauth2: ["functions:/api/v1/mcp:read"]}). We mirror them
		// into the "oauth2" bucket here.
		//
		// This is guarded on the PATBridgeClaim marker, which is set ONLY by
		// the proxy PAT bridge — NOT on auth_method=="oauth2" (an ordinary
		// JWT-cookie user who logged in via oauth2 also carries that method
		// but must keep bearer-only bucketing). JWT/cookie/apiKey callers do
		// not carry this marker, so their bucketing is byte-for-byte
		// unchanged. See kdex-tech/host-manager §4.
		if authContext.IsPATBridge() {
			userEntitlements["oauth2"] = contextEntitlements
		}
	}

	contextScopes, _ := authContext.GetScopes()
	if len(contextScopes) > 0 {
		authMethod, _ := authContext.GetAuthMethod()
		switch authMethod {
		case AuthMethodOIDC:
			userEntitlements["oidc"] = contextScopes
		case AuthMethodOAuth2:
			userEntitlements["oauth2"] = contextScopes
		}
	}

	return ac.ParseEntitlements(userEntitlements)
}

func (ac *AuthorizationChecker) ParseEntitlements(e entitlements.Entitlements) entitlements.ParsedEntitlements {
	return ac.ec.ParseEntitlements(e)
}

func (ac *AuthorizationChecker) ParseRequirements(kdexreqs []kdexv1alpha1.SecurityRequirement) (result entitlements.ParsedRequirements) {
	// Defensive recover: a corrupted slice header (nil data + non-zero len,
	// as observed in production via a DeepCopy edge case on a value-struct
	// SecurityRequirements field) makes `range kdexreqs` segfault. The
	// caller is typically holding a read lock (RebuildMux); a panic here
	// must not propagate up far enough to leak that lock. Returning an
	// empty parsed-requirements set on panic preserves liveness — the
	// affected page falls through to anonymous-access semantics, but the
	// host as a whole keeps reconciling. See kdex-tech/host-manager#26.
	defer func() {
		if r := recover(); r != nil {
			ac.log.Error(nil, "ParseRequirements panic recovered", "panic", r)
			result = ac.ec.ParseRequirements(entitlements.Requirements{})
		}
	}()
	if len(kdexreqs) == 0 {
		return ac.ec.ParseRequirements(entitlements.Requirements{})
	}
	requirements := make(entitlements.Requirements, 0, len(kdexreqs))
	for i := range kdexreqs {
		requirements = append(requirements, kdexreqs[i])
	}
	return ac.ec.ParseRequirements(requirements)
}

// BindRequirements substitutes each {placeholder} resourceName in reqs with its
// bound value. Delegates to the entitlements checker; see its doc comment for
// the error contract (ErrUnboundPlaceholder / ErrInvalidBoundValue /
// ErrWildcardRequirement).
func (ac *AuthorizationChecker) BindRequirements(
	reqs entitlements.ParsedRequirements,
	binding entitlements.Binding,
) (entitlements.ParsedRequirements, error) {
	return ac.ec.BindRequirements(reqs, binding)
}

func (ac *AuthorizationChecker) VerifyResourceParsedEntitlements(
	resource string,
	resourceName string,
	parsedEntitlements entitlements.ParsedEntitlements,
	parsedRequirements entitlements.ParsedRequirements,
	verbs ...string,
) (bool, error) {
	return ac.ec.VerifyResourceParsedEntitlements(resource, resourceName, parsedEntitlements, parsedRequirements, verbs...)
}
