package host

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kdex-tech/entitlements"
	"kdex.dev/crds/api/v1alpha1"
)

type CheckRequest struct {
	Checks []string `json:"checks"`
}

type CheckResponse struct {
	Passed []string `json:"passed"`
}

func (hh *HostHandler) CheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	if hh.authChecker == nil {
		// If auth is disabled, return empty or all?
		// Usually if checker is nil, auth is disabled and everything passes.
		// However, KDex tech usually requires explicit grants.
		err := json.NewEncoder(w).Encode(CheckResponse{Passed: []string{}})
		if err != nil {
			hh.log.Error(err, "failed to encode check response")
		}
		return
	}

	// 1. Pre-parse user entitlements once
	parsedUserEntitlements := hh.authChecker.GetParsedEntitlements(r.Context())
	passed := []string{}

	for _, check := range req.Checks {
		parts := strings.Split(check, ":")
		if len(parts) != 3 {
			continue // Invalid format
		}

		resource := parts[0]
		resourceName := parts[1]
		verb := parts[2]

		var requirements entitlements.ParsedRequirements
		found := false

		switch resource {
		case "pages":
			// Try to find the page handler to get pre-parsed requirements
			for _, ph := range hh.Pages.List() {
				if ph.BasePath() == resourceName {
					if ph.ParsedRequirements != nil {
						requirements = *ph.ParsedRequirements
						found = true
					}
					break
				}
			}
		case "functions":
			// Try to find the function handler to get pre-parsed requirements
			if fh, ok := hh.functionHandlers[resourceName]; ok {
				key := strings.ToUpper(verb) + " " + resourceName
				if pr, ok := fh.parsedRequirements[key]; ok {
					requirements = pr
					found = true
				} else {
					// Default to empty requirements for the function identity check
					requirements = hh.authChecker.ParseRequirements(nil)
					found = true
				}
			}
		}

		if !found {
			// Fallback: Just check if user has the identity entitlement for an unknown resource
			// using empty requirements.
			requirements = hh.authChecker.ParseRequirements([]v1alpha1.SecurityRequirement{})
		}

		authorized, err := hh.authChecker.VerifyResourceParsedEntitlements(
			resource, resourceName, parsedUserEntitlements, requirements, verb)

		if err == nil && authorized {
			passed = append(passed, check)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(CheckResponse{Passed: passed})
	if err != nil {
		hh.log.Error(err, "failed to encode check response")
	}
}
