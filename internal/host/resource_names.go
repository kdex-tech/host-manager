package host

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	openapi "github.com/getkin/kin-openapi/openapi3"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	resourceNamesPath = "/-/entitlements/resources/{resource}/names"

	// kdexResourceListingExtension declares, on a function's GET operation,
	// that it lists the instances of a resource the function owns:
	//   x-kdex-resource-listing: {resource: roles}
	// The operation answers {items: [{name, label?}], next?} -- name is the
	// resourceName used in entitlements, label its human-readable name -- and
	// takes the same parameters the host serves:
	//   ?q=      type-ahead: a case-insensitive substring of name OR label
	//   ?limit=  page size (the host forwards 1..200; never return more)
	//   ?cursor= the previous page's next, opaque to the host
	// See kdex-tech/host-manager#232.
	kdexResourceListingExtension = "x-kdex-resource-listing"

	resourceNamesDefaultLimit = 50
	resourceNamesMaxLimit     = 200
	// maxListingResponseBytes bounds what the host buffers from an owner.
	maxListingResponseBytes = 1 << 20
)

// hostNativeResources are listed by the host itself and cannot be claimed by a
// function's listing declaration.
var hostNativeResources = []string{"pages", "functions"}

type resourceName struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
}

type resourceNamesPage struct {
	Items []resourceName `json:"items"`
	Next  string         `json:"next,omitempty"`
}

// resourceNamesHandler lists the instance names of a resource, for a role
// builder's "pick a name" step. See kdex-tech/host-manager#232.
//
//   - pages and functions are answered by the host: the pages and (ready,
//     non-internal) functions whose gate the caller passes.
//   - any other resource is answered by the function that declares
//     x-kdex-resource-listing for it. The request is re-dispatched into the
//     host's own mux to that function's route, so the function's own gate,
//     FAT and binding run with the caller's credentials, and the owner
//     returns only instances the caller may see. Only q and cursor are
//     forwarded.
//
// ?verb= narrows the answer to names the caller can grant for that verb
// (entitlements.VerifyAttenuation against the token's entitlements, as
// mint_token does). Two functions declaring the same resource is a
// configuration fault: neither is chosen.
func (hh *HostHandler) resourceNamesHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if hh.authChecker == nil {
		return // auth disabled: no caller to list for
	}

	mux.HandleFunc("GET "+resourceNamesPath, func(w http.ResponseWriter, r *http.Request) {
		log := logf.FromContext(r.Context())
		ac, ok := auth.GetAuthContext(r.Context())
		if !ok {
			denial.Write(w, r, denial.Opts{Outcome: denial.Unauthenticated, Issuer: hh.issuerAddress()})
			return
		}
		held := stringSliceFromClaim(ac["entitlements"])
		resource := r.PathValue("resource")
		query := r.URL.Query()
		q, cursor, verb := query.Get("q"), query.Get("cursor"), query.Get("verb")
		limit := resourceNamesDefaultLimit
		if v := query.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > resourceNamesMaxLimit {
				http.Error(w, fmt.Sprintf("limit must be 1..%d", resourceNamesMaxLimit), http.StatusBadRequest)
				return
			}
			limit = n
		}

		var result resourceNamesPage
		if slices.Contains(hostNativeResources, resource) {
			page, err := pageOfNames(hh.hostNativeNames(r, resource), q, cursor, limit)
			if err != nil {
				http.Error(w, "invalid cursor", http.StatusBadRequest)
				return
			}
			result = page
		} else {
			hh.mu.RLock()
			route, err := listingRoute(hh.registeredPaths, resource)
			hh.mu.RUnlock()
			if err != nil {
				log.Error(err, "resource listing is misconfigured", "resource", resource)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if route == "" {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			page, status, header := dispatchListing(mux, r, route, q, cursor, limit)
			if status != http.StatusOK {
				// The owner's own gate decided (401/403/...): pass its
				// verdict through, keeping its challenge.
				if v := header.Get("WWW-Authenticate"); v != "" {
					w.Header().Set("WWW-Authenticate", v)
				}
				http.Error(w, http.StatusText(status), status)
				return
			}
			if page == nil {
				log.Error(nil, "resource listing returned a malformed response", "resource", resource, "route", route)
				http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
				return
			}
			result = *page
		}

		if verb != "" {
			result.Items = slices.DeleteFunc(result.Items, func(n resourceName) bool {
				_, ok := entitlements.VerifyAttenuation(held, []string{resource + ":" + n.Name + ":" + verb})
				return !ok
			})
		}
		if result.Items == nil {
			result.Items = []resourceName{}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		_ = json.NewEncoder(w).Encode(result)
	})

	hh.registerPath(resourceNamesPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: resourceNamesPath,
			Paths: map[string]ko.PathItem{
				resourceNamesPath: {
					Description: "Lists the instance names of a resource the caller may see.",
					Get: &openapi.Operation{
						Description: "pages and functions are answered by the host; any other resource by the function " +
							"declaring " + kdexResourceListingExtension + " for it, called with the caller's credentials. " +
							"?verb= keeps only names the caller can grant for that verb.",
						OperationID: "entitlement-resource-names-get",
						Parameters: openapi.Parameters{
							&openapi.ParameterRef{Value: &openapi.Parameter{
								Name: "resource", In: "path", Required: true,
								Schema: openapi.NewSchemaRef("", openapi.NewStringSchema()),
							}},
							&openapi.ParameterRef{Value: &openapi.Parameter{
								Name: "q", In: "query", Description: "Type-ahead: a case-insensitive substring of name or label.",
								Schema: openapi.NewSchemaRef("", openapi.NewStringSchema()),
							}},
							&openapi.ParameterRef{Value: &openapi.Parameter{
								Name: "cursor", In: "query", Description: "The previous page's next (opaque).",
								Schema: openapi.NewSchemaRef("", openapi.NewStringSchema()),
							}},
							&openapi.ParameterRef{Value: &openapi.Parameter{
								Name: "limit", In: "query", Description: "Page size, 1..200 (default 50).",
								Schema: openapi.NewSchemaRef("", openapi.NewIntegerSchema()),
							}},
							&openapi.ParameterRef{Value: &openapi.Parameter{
								Name: "verb", In: "query", Description: "Keep only names grantable for this verb.",
								Schema: openapi.NewSchemaRef("", openapi.NewStringSchema()),
							}},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content:     openapi.NewContentWithSchema(&openapi.Schema{Type: &openapi.Types{openapi.TypeObject}}, []string{"application/json"}),
								Description: new("{items: [{name, label?}], next?}"),
							}),
							openapi.WithStatus(401, &openapi.ResponseRef{Ref: ko.RespRefUnauthorized}),
							openapi.WithStatus(404, &openapi.ResponseRef{Ref: ko.RespRefNotFound}),
						),
						Summary: "Resource names",
						Tags:    []string{"system", "auth", "entitlements"},
					},
					Summary: "Resource names",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

// hostNativeNames returns the names of a host-native resource the caller
// passes the gate for, using the gate's own rule: a page with no requirements
// is public, otherwise VerifyResourceParsedEntitlements decides; a function's
// identity requirement (functions:<basePath>:read) always applies.
func (hh *HostHandler) hostNativeNames(r *http.Request, resource string) []resourceName {
	held := hh.authChecker.GetParsedEntitlements(r.Context())
	none := hh.authChecker.ParseRequirements(nil)

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	seen := map[string]struct{}{}
	var out []resourceName
	add := func(name, label string) {
		if _, dup := seen[name]; name == "" || dup {
			return
		}
		seen[name] = struct{}{}
		out = append(out, resourceName{Name: name, Label: label})
	}
	switch resource {
	case "pages":
		for _, ph := range hh.Pages.List() {
			if ph.ParsedRequirements != nil {
				if ok, err := hh.authChecker.VerifyResourceParsedEntitlements(
					"pages", ph.BasePath(), held, *ph.ParsedRequirements); err != nil || !ok {
					continue
				}
			}
			label := ""
			if ph.Page != nil {
				label = ph.Page.Label
			}
			add(ph.BasePath(), label)
		}
	case "functions":
		for _, fn := range hh.functions {
			if fn.Spec.Internal || fn.Status.State != kdexv1alpha1.KDexFunctionStateReady {
				continue
			}
			if ok, err := hh.authChecker.VerifyResourceParsedEntitlements(
				"functions", fn.Spec.API.BasePath, held, none); err != nil || !ok {
				continue
			}
			add(fn.Spec.API.BasePath, fn.Name)
		}
	}
	return out
}

// pageOfNames applies, for host-native resources, the listing contract an
// owner also follows: q is a case-insensitive substring of the name OR the
// label (a type-ahead), items are sorted by label (name when unlabelled) then
// name, and an opaque cursor resumes after the previous page's last item.
func pageOfNames(all []resourceName, q, cursor string, limit int) (resourceNamesPage, error) {
	after, err := decodeNamesCursor(cursor)
	if err != nil {
		return resourceNamesPage{}, err
	}
	lq := strings.ToLower(q)
	var items []resourceName
	for _, n := range all {
		if lq != "" && !strings.Contains(strings.ToLower(n.Name), lq) && !strings.Contains(strings.ToLower(n.Label), lq) {
			continue
		}
		if after != nil && compareNames(n, *after) <= 0 {
			continue
		}
		items = append(items, n)
	}
	slices.SortFunc(items, compareNames)
	page := resourceNamesPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.Next = encodeNamesCursor(page.Items[limit-1])
	}
	return page, nil
}

// compareNames orders by label (name when unlabelled), case-insensitively,
// then by name, which is unique.
func compareNames(a, b resourceName) int {
	sortKey := func(n resourceName) string {
		if n.Label != "" {
			return strings.ToLower(n.Label)
		}
		return strings.ToLower(n.Name)
	}
	if c := strings.Compare(sortKey(a), sortKey(b)); c != 0 {
		return c
	}
	return strings.Compare(a.Name, b.Name)
}

// A host cursor is the last item of the previous page, so it resumes correctly
// even if items were added or removed in between.
func encodeNamesCursor(last resourceName) string {
	b, _ := json.Marshal(last)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeNamesCursor(cursor string) (*resourceName, error) {
	if cursor == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, err
	}
	var last resourceName
	if err := json.Unmarshal(b, &last); err != nil || last.Name == "" {
		return nil, fmt.Errorf("invalid cursor")
	}
	return &last, nil
}

// listingRoute returns the concrete route of the function operation declaring
// x-kdex-resource-listing for resource, "" when none does, or an error when
// more than one route does (never pick one silently). Host-native resources
// cannot be claimed, and a route with a {param} is not a listing.
func listingRoute(paths map[string]ko.PathInfo, resource string) (string, error) {
	if slices.Contains(hostNativeResources, resource) {
		return "", nil
	}
	var routes []string
	for _, info := range paths {
		if info.Type != ko.FunctionPathType {
			continue
		}
		for route, item := range info.API.Paths {
			if item.Get == nil || strings.Contains(route, "{") ||
				listingResource(item.Get.Extensions[kdexResourceListingExtension]) != resource {
				continue
			}
			if !slices.Contains(routes, route) {
				routes = append(routes, route)
			}
		}
	}
	switch len(routes) {
	case 0:
		return "", nil
	case 1:
		return routes[0], nil
	}
	slices.Sort(routes)
	return "", fmt.Errorf("%d functions declare %s for resource %q: %v", len(routes), kdexResourceListingExtension, resource, routes)
}

// listingResource reads the declared resource from the extension value,
// whether built in code (map), decoded from a CR (map[string]any) or left raw.
func listingResource(v any) string {
	switch t := v.(type) {
	case map[string]any:
		s, _ := t["resource"].(string)
		return s
	case json.RawMessage:
		var decl struct {
			Resource string `json:"resource"`
		}
		if json.Unmarshal(t, &decl) == nil {
			return decl.Resource
		}
	}
	return ""
}

// dispatchListing re-dispatches a clone of r -- the caller's context and
// credentials -- as GET route?q=&cursor=&limit= into mux, the snapshot this handler
// was registered into (as rewrite mode does), and buffers the answer. It
// returns the parsed page on a 200 with a well-formed body, nil on a malformed
// one (an item without a name, or more items than limit), and always the
// owner's status and headers.
func dispatchListing(mux *http.ServeMux, r *http.Request, route, q, cursor string, limit int) (*resourceNamesPage, int, http.Header) {
	vals := url.Values{"limit": {strconv.Itoa(limit)}}
	if q != "" {
		vals.Set("q", q)
	}
	if cursor != "" {
		vals.Set("cursor", cursor)
	}
	r2 := r.Clone(r.Context())
	r2.Method = http.MethodGet
	r2.URL.Path = route
	r2.URL.RawPath = ""
	r2.URL.RawQuery = vals.Encode()
	r2.RequestURI = r2.URL.RequestURI()
	r2.Body = http.NoBody
	r2.ContentLength = 0

	buf := &bufferedResponse{header: http.Header{}, status: http.StatusOK}
	mux.ServeHTTP(buf, r2)
	if buf.status != http.StatusOK {
		return nil, buf.status, buf.header
	}
	if buf.overflow {
		return nil, http.StatusOK, buf.header
	}
	var page resourceNamesPage
	if err := json.Unmarshal(buf.body.Bytes(), &page); err != nil || len(page.Items) > limit {
		return nil, http.StatusOK, buf.header
	}
	for _, item := range page.Items {
		if item.Name == "" {
			return nil, http.StatusOK, buf.header
		}
	}
	return &page, http.StatusOK, buf.header
}

// bufferedResponse captures a re-dispatched response, up to
// maxListingResponseBytes.
type bufferedResponse struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
	overflow    bool
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) {
	if !b.wroteHeader {
		b.status, b.wroteHeader = status, true
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	b.WriteHeader(http.StatusOK)
	if b.body.Len()+len(p) > maxListingResponseBytes {
		b.overflow = true
		return len(p), nil
	}
	return b.body.Write(p)
}
