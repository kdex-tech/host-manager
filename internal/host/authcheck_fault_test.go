/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// errCheckerFailure is what a checker that could not reach a verdict returns.
var errCheckerFailure = errors.New("entitlement pattern cache is unavailable")

// faultyChecker's VerifyResourceParsedEntitlements ERRORS -- it never reaches a
// verdict, so nothing is known about the caller either way. Distinct from a
// checker that returns (false, nil), which is a decision.
type faultyChecker struct{}

func (faultyChecker) CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return nil, nil
}
func (faultyChecker) CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
	return false, errCheckerFailure
}
func (faultyChecker) GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements {
	return entitlements.ParsedEntitlements{}
}
func (faultyChecker) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return entitlements.ParsedRequirements{}
}
func (faultyChecker) BindRequirements(reqs entitlements.ParsedRequirements, _ entitlements.Binding) (entitlements.ParsedRequirements, error) {
	return reqs, nil
}
func (faultyChecker) VerifyResourceParsedEntitlements(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error) {
	return false, errCheckerFailure
}

// An authorization check that FAILED TO RUN is a server fault, not a denial.
// Both gates used to fold `err != nil` into `!authorized` and render the whole
// thing through denial.Write, which misattributes an operator's outage to the
// visitor: the caller is told it may not have the resource when in truth
// nothing was decided about the caller at all.
//
// The contract governs denials. A fault is neither a denial nor an absence, so
// it sits deliberately outside the three-row table and takes no status, and no
// challenge, from it.
func TestPageGateErroredCheckIs500NotADenial(t *testing.T) {
	// Both caller shapes: the fault must not be reclassified by who asked.
	// Anonymous is the one that would otherwise have become 401 + challenge
	// (or a login redirect); an authenticated caller would have become 403.
	for name, req := range map[string]*http.Request{
		"anonymous/html":     anonReq("GET", "/developer-keys", "text/html"),
		"anonymous/json":     anonReq("GET", "/developer-keys", "application/json"),
		"authenticated/html": subjectlessReq("GET", "/developer-keys", "text/html", auth.AuthContext{"sub": "alice"}),
	} {
		t.Run(name, func(t *testing.T) {
			gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
			hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
			hh.authChecker = faultyChecker{}

			w := httptest.NewRecorder()
			hh.pageHandlerFunc(gated, &hh.Translations)(w, req)

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500: a check that failed to run says nothing "+
					"about the caller, so it is a server fault and not a denial", w.Code)
			}
			if got := w.Header().Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q; a 500 carries no challenge -- no credential "+
					"the caller could present would make the checker run", got)
			}
			if loc := w.Header().Get("Location"); loc != "" {
				t.Fatalf("Location = %q; a fault is not a login redirect and not a discovery "+
					"redirect", loc)
			}
		})
	}
}

// The same ruling at the FUNCTION PROXY gate, so the two gates agree. This one
// is where the missing challenge matters most: an MCP client reading a 401 +
// resource_metadata would go off and re-authorize over a failure no credential
// can address.
func TestProxyGateErroredCheckIs500NotADenial(t *testing.T) {
	logf.SetLogger(logr.Discard())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	basePath := "/api/v1/mcp"
	fn := newReadyFunctionWithOAuth2(t, basePath, []string{"functions:" + basePath + ":read"})
	fn.Status.URL = upstream.URL

	cacheManager, _ := cache.NewCacheManager("", "authcheck-fault-test", nil)
	hh := &HostHandler{
		log:          logr.Discard(),
		scheme:       "https",
		cacheManager: cacheManager,
		authChecker:  faultyChecker{},
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{"dev.knowdrive.ai"}},
		},
		functions:  []kdexv1alpha1.KDexFunction{fn},
		authConfig: challengeFixtureAuthConfig(t),
	}
	h := hh.reverseProxyHandler(&fn, "https://dev.knowdrive.ai")

	req := httptest.NewRequest(http.MethodPost, basePath, strings.NewReader("{}"))
	req.Host = "dev.knowdrive.ai"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: this path is oauth2-protected, so folding the "+
			"fault into the denial answers 401 + resource_metadata and sends an MCP client "+
			"to re-authorize over an outage", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate = %q, want none on a 500", got)
	}
}
