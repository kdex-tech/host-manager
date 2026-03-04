package auth

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/entitlements"
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
) (bool, error) {
	if resource == "" || resourceName == "" {
		return false, fmt.Errorf("resource and resourceName must not be empty")
	}

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

	requirements := entitlements.Requirements{}
	for _, v := range kdexreqs {
		requirements = append(requirements, v)
	}

	ac.log.V(2).Info("CheckAccess", "claim", authContext, "entitlements", userEntitlements, "requirements", requirements)

	return ac.ec.VerifyResourceEntitlements(resource, resourceName, userEntitlements, requirements)
}

func (ac *AuthorizationChecker) CalculateRequirements(
	resource string,
	resourceName string,
	kdexreqs []kdexv1alpha1.SecurityRequirement,
) ([]kdexv1alpha1.SecurityRequirement, error) {
	if resource == "" || resourceName == "" {
		return nil, fmt.Errorf("resource and resourceName must not be empty")
	}

	requirements := entitlements.Requirements{}
	for _, v := range kdexreqs {
		requirements = append(requirements, v)
	}

	requirements, err := ac.ec.CalculateResourceRequirements(resource, resourceName, requirements)
	if err != nil {
		return nil, err
	}

	kreq := make([]kdexv1alpha1.SecurityRequirement, 0, len(requirements))
	for _, v := range requirements {
		kreq = append(kreq, v)
	}

	return kreq, nil
}
