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

// ParseRequirements converts a CRD-shaped SecurityRequirement slice into the
// entitlements package's Requirements form. It recovers from any panic
// (e.g. a JSON-decoded or DeepCopy-corrupted slice header reaching the
// range loop) and returns an empty ParsedRequirements rather than
// propagating, because in callers like host.RebuildMux a panic here would
// unwind through a non-deferred RLock and deadlock every subsequent
// reconcile. See kdex-tech/host-manager#26.
func (ac *AuthorizationChecker) ParseRequirements(kdexreqs []kdexv1alpha1.SecurityRequirement) (result entitlements.ParsedRequirements) {
	defer func() {
		if r := recover(); r != nil {
			ac.log.Error(fmt.Errorf("%v", r), "recovered from panic in ParseRequirements; returning empty requirements", "len", len(kdexreqs))
			result = ac.ec.ParseRequirements(entitlements.Requirements{})
		}
	}()

	requirements := entitlements.Requirements{}
	for _, v := range kdexreqs {
		requirements = append(requirements, v)
	}
	return ac.ec.ParseRequirements(requirements)
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
