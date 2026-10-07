package host

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	openapi "github.com/getkin/kin-openapi/openapi3"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
)

const (
	entitlementCatalogPath = "/-/entitlements/catalog"

	// kdexEntitlementsExtension is the machine-readable operation extension
	// for requirements an operation checks in handler code rather than at the
	// gate (e.g. one whose value comes from the request body, which
	// x-entitlement-binding cannot read). Unlike the prose
	// x-required-entitlement, every entry is a requirement string the catalog
	// parses. See kdex-tech/host-manager#232.
	kdexEntitlementsExtension = "x-kdex-entitlements"
)

// entitlementCatalogHandler serves which entitlements can be expressed on this
// host: the (resource, verb) pairs and the opaque scopes that something on the
// site actually checks, built from the same registered paths /-/openapi
// serves. A role builder offers these as closed choices instead of free text.
// See kdex-tech/host-manager#232.
//
// By default the catalog is clamped to what the caller holds -- the token's
// entitlements, the set mint_token attenuates against -- so it offers only
// what the caller could grant. It is advice for a UI, not enforcement: a
// writer must still check what it stores with entitlements.VerifyAttenuation.
// ?all=true returns the unclamped catalog, which says no more than the public
// /-/openapi, so it needs no caller.
func (hh *HostHandler) entitlementCatalogHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	mux.HandleFunc("GET "+entitlementCatalogPath, func(w http.ResponseWriter, r *http.Request) {
		hh.mu.RLock()
		pairs, scopes := declaredEntitlements(hh.registeredPaths)
		hh.mu.RUnlock()

		if r.URL.Query().Get("all") == "true" {
			writeCatalog(w, catalogFrom(pairs, scopes, nil))
			return
		}

		ac, ok := auth.GetAuthContext(r.Context())
		if !ok {
			denial.Write(w, r, denial.Opts{Outcome: denial.Unauthenticated, Issuer: hh.issuerAddress()})
			return
		}
		held := stringSliceFromClaim(ac["entitlements"])
		writeCatalog(w, catalogFrom(pairs, scopes, held))
	})

	hh.registerPath(entitlementCatalogPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: entitlementCatalogPath,
			Paths: map[string]ko.PathItem{
				entitlementCatalogPath: {
					Description: "The entitlements that can be expressed on this host.",
					Get: &openapi.Operation{
						Description: "Lists the (resource, verb) pairs and opaque scopes something on this host checks: " +
							"every operation's security requirements and " + kdexEntitlementsExtension + " entries, " +
							"plus the implicit pages/read and functions/read identities. Clamped to the caller's " +
							"held entitlements by default (\"all\" when a held entitlement covers every name, else " +
							"the specific names held); ?all=true returns it unclamped. Advice for a UI, not enforcement.",
						OperationID: "entitlement-catalog-get",
						Parameters: openapi.Parameters{
							&openapi.ParameterRef{Value: &openapi.Parameter{
								Name:        "all",
								In:          "query",
								Description: "true returns the unclamped catalog (no caller needed).",
								Schema:      openapi.NewSchemaRef("", openapi.NewBoolSchema()),
							}},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content:     openapi.NewContentWithSchema(&openapi.Schema{Type: &openapi.Types{openapi.TypeObject}}, []string{"application/json"}),
								Description: new("{resources: [{resource, verbs: [{verb, all?, names?}]}], scopes: [...]}"),
							}),
							openapi.WithStatus(401, &openapi.ResponseRef{Ref: ko.RespRefUnauthorized}),
						),
						Summary: "Entitlement catalog",
						Tags:    []string{"system", "auth", "entitlements"},
					},
					Summary: "Entitlement catalog",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

// declaredEntitlements walks the registered paths and returns every declared
// (resource -> verbs) pair and every opaque scope. A requirement that is not
// well-formed (entitlements.ValidateRequirement) is skipped rather than
// misreported -- the lenient verification parser would read "a:b:c:d" as an
// opaque scope.
func declaredEntitlements(paths map[string]ko.PathInfo) (map[string]map[string]struct{}, map[string]struct{}) {
	pairs := map[string]map[string]struct{}{}
	scopes := map[string]struct{}{}
	addPair := func(resource, verb string) {
		if pairs[resource] == nil {
			pairs[resource] = map[string]struct{}{}
		}
		pairs[resource][verb] = struct{}{}
	}
	add := func(req string) {
		if entitlements.ValidateRequirement(req) != nil {
			return
		}
		parts := strings.Split(req, ":")
		switch len(parts) {
		case 1:
			scopes[req] = struct{}{}
		case 2:
			addPair(parts[0], parts[1])
		case 3:
			addPair(parts[0], parts[2])
		}
	}

	for _, info := range paths {
		// The gate's implicit identity requirements never appear in a spec.
		switch info.Type {
		case ko.PagePathType:
			addPair("pages", "read")
		case ko.FunctionPathType:
			addPair("functions", "read")
		}
		for _, item := range info.API.Paths {
			for _, op := range pathItemOperations(item) {
				if op.Security != nil {
					for _, sr := range *op.Security {
						for _, reqs := range sr {
							for _, req := range reqs {
								add(req)
							}
						}
					}
				}
				for _, req := range extensionStrings(op.Extensions[kdexEntitlementsExtension]) {
					add(req)
				}
			}
		}
	}
	return pairs, scopes
}

func pathItemOperations(item ko.PathItem) []*openapi.Operation {
	ops := make([]*openapi.Operation, 0, 2)
	for _, op := range []*openapi.Operation{
		item.Connect, item.Delete, item.Get, item.Head, item.Options,
		item.Patch, item.Post, item.Put, item.Trace,
	} {
		if op != nil {
			ops = append(ops, op)
		}
	}
	return ops
}

// extensionStrings reads a string-array extension value whether it was built
// in code ([]string), decoded from a CR ([]any), or left raw (json.RawMessage).
// Anything else yields nothing.
func extensionStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case json.RawMessage:
		var out []string
		if json.Unmarshal(t, &out) == nil {
			return out
		}
	}
	return nil
}

type entitlementCatalog struct {
	Resources []catalogResource `json:"resources"`
	Scopes    []string          `json:"scopes"`
}

type catalogResource struct {
	Resource string              `json:"resource"`
	Verbs    []catalogVerbChoice `json:"verbs"`
}

type catalogVerbChoice struct {
	Verb string `json:"verb"`
	// All is set when the caller may grant the verb for every name. Nil when
	// the catalog is unclamped.
	All *bool `json:"all,omitempty"`
	// Names are the specific names the caller holds the verb for, when All
	// is false.
	Names []string `json:"names,omitempty"`
}

// catalogFrom builds the response. With held == nil it is unclamped; otherwise
// a pair is kept only when some held entitlement dominates it for some name,
// and a scope only when it is held exactly. Dominance is entitlements.Dominates,
// the attenuation predicate, so the catalog can never offer more than a
// VerifyAttenuation check at save time would accept.
func catalogFrom(pairs map[string]map[string]struct{}, scopes map[string]struct{}, held []string) entitlementCatalog {
	clamp := held != nil
	cat := entitlementCatalog{Resources: []catalogResource{}, Scopes: []string{}}

	for _, resource := range sortedKeys(pairs) {
		res := catalogResource{Resource: resource}
		for _, verb := range sortedKeys(pairs[resource]) {
			if !clamp {
				res.Verbs = append(res.Verbs, catalogVerbChoice{Verb: verb})
				continue
			}
			all, names := grantable(held, resource, verb)
			if !all && len(names) == 0 {
				continue
			}
			choice := catalogVerbChoice{Verb: verb, All: new(all)}
			if !all {
				choice.Names = names
			}
			res.Verbs = append(res.Verbs, choice)
		}
		if len(res.Verbs) > 0 {
			cat.Resources = append(cat.Resources, res)
		}
	}

	for _, scope := range sortedKeys(scopes) {
		if !clamp || slices.Contains(held, scope) {
			cat.Scopes = append(cat.Scopes, scope)
		}
	}
	return cat
}

// grantable reports whether the held set dominates resource:*:verb (all), and
// otherwise the specific names it dominates resource:<name>:verb for.
func grantable(held []string, resource, verb string) (bool, []string) {
	var names []string
	for _, h := range held {
		parts := strings.Split(h, ":")
		if len(parts) < 2 || len(parts) > 3 || parts[0] != resource {
			continue
		}
		if entitlements.Dominates(h, resource+":*:"+verb) {
			return true, nil
		}
		if len(parts) == 3 && entitlements.Dominates(h, resource+":"+parts[1]+":"+verb) &&
			!slices.Contains(names, parts[1]) {
			names = append(names, parts[1])
		}
	}
	slices.Sort(names)
	return false, names
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// writeCatalog writes the catalog. A clamped body depends on the caller's
// grants, so neither form is ever served from a shared cache.
func writeCatalog(w http.ResponseWriter, cat entitlementCatalog) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(cat)
}
