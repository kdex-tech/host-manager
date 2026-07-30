package host

import (
	"encoding/json"
	"net/http"
	"strings"

	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// maxCheckRequestBytes caps /check request bodies. CheckRequest is a short
// slice of strings; 64 KiB is far more than needed and bounds the
// memory-exhaustion DoS surface.
const maxCheckRequestBytes = 64 << 10

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
	if err := kdexhttp.DecodeJSONBody(w, r, maxCheckRequestBytes, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log := logf.FromContext(r.Context())

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	if hh.authChecker == nil {
		// If auth is disabled, return empty or all?
		// Usually if checker is nil, auth is disabled and everything passes.
		// However, KDex tech usually requires explicit grants.
		err := json.NewEncoder(w).Encode(CheckResponse{Passed: []string{}})
		if err != nil {
			log.Error(err, "failed to encode check response")
		}
		return
	}

	// /-/check is a batch entitlement-membership test: each check string passes
	// iff the caller holds a grant satisfying that exact
	// <resource>:<resourceName>:<verb>, using ordinary entitlement matching. The
	// check string IS the thing tested -- there is no per-resource branching and
	// no lookup of a page's or function's declared security. Consulting a
	// resource's own requirements is the gate's job on the real request; /-/check
	// only answers "does the caller hold this grant?" (An empty requirement set
	// reduces VerifyResourceParsedEntitlements to exactly that grant check for
	// the given verb.)
	parsedUserEntitlements := hh.authChecker.GetParsedEntitlements(r.Context())
	noRequirements := hh.authChecker.ParseRequirements(nil)
	passed := []string{}

	for _, check := range req.Checks {
		parts := strings.Split(check, ":")
		if len(parts) != 3 {
			continue // Invalid format
		}

		resource := parts[0]
		resourceName := parts[1]
		verb := parts[2]

		authorized, err := hh.authChecker.VerifyResourceParsedEntitlements(
			resource, resourceName, parsedUserEntitlements, noRequirements, verb)

		if err == nil && authorized {
			passed = append(passed, check)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(CheckResponse{Passed: passed})
	if err != nil {
		log.Error(err, "failed to encode check response")
	}
}
