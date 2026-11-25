package host

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// The /-/rolebindings gate lives HERE and nowhere else: roleAssignmentsReadScope
// (the grant) and canReadRoleBindings (the check). The handler, its OpenAPI
// text, its caching and the tests all derive from them, so renaming the
// entitlement is one edit.
//
// The gate is the kdex-roles contract's opaque scope role_assignments_read,
// the one the role service and eum already check before showing who holds a
// role. An opaque scope compiles verbatim and matches only by exact name, so
// no wildcard or `all` grant implies it.
const roleAssignmentsReadScope = "role_assignments_read"

// roleBindingsChecker is the part of the host's authorization checker the
// gate uses.
type roleBindingsChecker interface {
	HoldsScope(context.Context, string) bool
}

// canReadRoleBindings reports whether the caller may resolve subjects
// against the host's bindings: all of them or none.
func canReadRoleBindings(ctx context.Context, checker roleBindingsChecker) bool {
	return checker.HoldsScope(ctx, roleAssignmentsReadScope)
}

const (
	roleBindingsPath = "/-/rolebindings"

	// maxRoleBindingSubjects and maxRoleBindingSubjectLen bound the regex
	// work one request can cause: every subject runs every pattern binding.
	maxRoleBindingSubjects   = 32
	maxRoleBindingSubjectLen = 1024
)

// roleBindingsResponse is the GET /-/rolebindings body.
type roleBindingsResponse struct {
	Subjects []subjectBindings `json:"subjects"`
}

// subjectBindings answers one requested subject.
type subjectBindings struct {
	Subject  string                `json:"subject"`
	Kind     string                `json:"kind"`
	Bindings []auth.MatchedBinding `json:"bindings"`
	// Roles is the sorted, de-duplicated union of the roles of the admitted
	// bindings: what the subject resolves to.
	Roles []string `json:"roles"`
}

// roleBindingsHandler resolves subjects against the host's KDexRoleBindings
// with host-manager's own matcher, so a companion service (a roles service
// reporting static assignments, eum's static roles) answers with the rule the
// host enforces instead of a copy of it. See kdex-tech/host-manager#303.
//
// It answers from the table auth.NewRoleProvider compiled at the last host
// reconcile: no request reaches the API server, and a binding change appears
// after the next reconcile.
//
// Bindings name user identifiers, so the route is gated, all or nothing, on
// roleAssignmentsReadScope (canReadRoleBindings). Unauthenticated is 401; a
// caller without the scope is 403, decided before the parameters are read; a
// bad parameter is 400. A 200 is never a partial view: an empty answer means
// the subject has no static roles.
func (hh *HostHandler) roleBindingsHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if hh.authChecker == nil {
		return // auth disabled: nothing to gate the bindings on
	}
	ex := hh.authExchanger
	checker := hh.authChecker

	mux.HandleFunc("GET "+roleBindingsPath, func(w http.ResponseWriter, r *http.Request) {
		ac, ok := auth.GetAuthContext(r.Context())
		if !ok {
			denial.Write(w, r, denial.Opts{Outcome: denial.Unauthenticated, Issuer: hh.issuerAddress()})
			return
		}
		if !canReadRoleBindings(r.Context(), checker) {
			// An opaque scope names no resource, so there is no identity
			// gate for denial.Classify to probe: past Classify's anonymity
			// rule (a context naming no subject is Unauthenticated) the
			// caller simply lacks the scope.
			outcome := denial.InsufficientScope
			if sub, _ := ac.GetSubject(); sub == "" {
				outcome = denial.Unauthenticated
			}
			denial.Write(w, r, denial.Opts{
				Outcome: outcome,
				Issuer:  hh.issuerAddress(),
				Scopes:  []string{roleAssignmentsReadScope},
			})
			return
		}

		query := r.URL.Query()
		subjects := query["subject"]
		if len(subjects) == 0 {
			http.Error(w, "subject is required", http.StatusBadRequest)
			return
		}
		if len(subjects) > maxRoleBindingSubjects {
			http.Error(w, "too many subjects", http.StatusBadRequest)
			return
		}
		for _, s := range subjects {
			if s == "" {
				http.Error(w, "subject must not be empty", http.StatusBadRequest)
				return
			}
			if len(s) > maxRoleBindingSubjectLen {
				http.Error(w, "subject too long", http.StatusBadRequest)
				return
			}
		}
		kinds := query["kind"]
		if len(kinds) > 1 {
			http.Error(w, "kind must be given at most once", http.StatusBadRequest)
			return
		}
		var kind kdexv1alpha1.SubjectKind
		if len(kinds) == 1 {
			kind = kdexv1alpha1.SubjectKind(kinds[0])
		}

		matcher := ex.Bindings()
		digest := ""
		if matcher != nil {
			digest = matcher.BindingsDigest()
		}

		body := roleBindingsResponse{Subjects: make([]subjectBindings, 0, len(subjects))}
		for _, s := range subjects {
			sb := subjectBindings{Subject: s, Kind: string(kind), Bindings: []auth.MatchedBinding{}, Roles: []string{}}
			if matcher != nil {
				for _, b := range matcher.MatchBindings(s, kind) {
					sb.Bindings = append(sb.Bindings, b)
					if b.Admitted {
						sb.Roles = append(sb.Roles, b.Roles...)
					}
				}
				slices.Sort(sb.Roles)
				sb.Roles = slices.Compact(sb.Roles)
			}
			body.Subjects = append(body.Subjects, sb)
		}

		if hh.writeRoleBindingsHeaders(w, r, digest) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	hh.registerPath(roleBindingsPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: roleBindingsPath,
			Paths: map[string]ko.PathItem{
				roleBindingsPath: {
					Description: "Resolves subjects against the host's KDexRoleBindings with the host's own matcher.",
					Get:         roleBindingsOperation(),
					Summary:     "Resolve a subject's KDexRoleBindings",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

// writeRoleBindingsHeaders sets the caching headers and reports whether the
// request was answered 304. The body depends on the binding table and is
// served only to callers holding the scope, so it is private and revalidated:
// the ETag carries the table's digest and, through
// applyCachingHeadersWithSeed, the caller's identity. With auth enabled on the checker but not on the config (no
// signing key yet) that helper would call the response public, so it is
// sent private, no-store instead.
func (hh *HostHandler) writeRoleBindingsHeaders(w http.ResponseWriter, r *http.Request, digest string) bool {
	hh.mu.RLock()
	defer hh.mu.RUnlock()
	requirements := []kdexv1alpha1.SecurityRequirement{{"bearer": {roleAssignmentsReadScope}}}
	if !hh.isPrivateResponse(requirements) {
		w.Header().Set("Cache-Control", "private, no-store")
		return false
	}
	return hh.applyCachingHeadersWithSeed(w, r, requirements, hh.reconcileTime, "", "rolebindings-"+digest)
}

func roleBindingsOperation() *openapi.Operation {
	strArray := func(desc string) *openapi.SchemaRef {
		return &openapi.SchemaRef{Value: &openapi.Schema{
			Type:        &openapi.Types{openapi.TypeArray},
			Description: desc,
			Items:       openapi.NewSchemaRef("", openapi.NewStringSchema()),
		}}
	}
	prop := func(s *openapi.Schema, desc string) *openapi.SchemaRef {
		s.Description = desc
		return &openapi.SchemaRef{Value: s}
	}
	binding := &openapi.SchemaRef{Value: &openapi.Schema{
		Type: &openapi.Types{openapi.TypeObject},
		Properties: openapi.Schemas{
			"name":    prop(openapi.NewStringSchema(), "The KDexRoleBinding's name."),
			"subject": prop(openapi.NewStringSchema(), "The binding's subject pattern as written: an exact subject, `*`, or a /regex/."),
			"admitted": prop(openapi.NewBoolSchema(),
				"Whether the binding's subjectKinds admits the requested kind. Only an admitted binding grants its roles."),
			"coverAll": prop(openapi.NewBoolSchema(),
				"The subject matches every subject: `*`, or a regex judged conservatively to match every string "+
					"(e.g. /.*/, /^.*$/). false does not prove a regex matches fewer subjects."),
			"roles": strArray("The binding's roles."),
		},
	}}
	subject := &openapi.SchemaRef{Value: &openapi.Schema{
		Type: &openapi.Types{openapi.TypeObject},
		Properties: openapi.Schemas{
			"subject": prop(openapi.NewStringSchema(), "The requested subject."),
			"kind":    prop(openapi.NewStringSchema(), "The requested kind; \"\" when none was given."),
			"bindings": &openapi.SchemaRef{Value: &openapi.Schema{
				Type:        &openapi.Types{openapi.TypeArray},
				Description: "The bindings whose subject matches, admitted or not, sorted by name.",
				Items:       binding,
			}},
			"roles": strArray("The sorted, de-duplicated union of the roles of the admitted bindings."),
		},
	}}
	security := &openapi.SecurityRequirements{
		openapi.SecurityRequirement{"bearer": {roleAssignmentsReadScope}},
	}
	return &openapi.Operation{
		Description: "Resolves each subject against the host's KDexRoleBindings with the host's own matcher " +
			"(exact, `*`, /regex/, subjectKinds), so a companion service answers with the rule the host enforces. " +
			"Served from the host's compiled bindings: no request reaches the API server, changes appear after " +
			"the next host reconcile, and callers need no cache of their own. " +
			"All or nothing: the caller must hold the kdex-roles contract's opaque scope " + roleAssignmentsReadScope +
			" (matched by exact name; no wildcard implies it), else 403, which a caller should treat as \"cannot tell\". " +
			"With it, every matching binding is returned, so an empty answer means the subject has no static roles.",
		OperationID: "rolebindings-resolve",
		Parameters: openapi.Parameters{
			&openapi.ParameterRef{Value: &openapi.Parameter{
				Name: "subject",
				In:   "query",
				Description: "A subject to resolve; repeat for several (at most 32, each at most 1024 bytes). " +
					"Answered in request order.",
				Required: true,
				Explode:  new(true),
				Schema: &openapi.SchemaRef{Value: &openapi.Schema{
					Type:  &openapi.Types{openapi.TypeArray},
					Items: openapi.NewSchemaRef("", openapi.NewStringSchema()),
				}},
			}},
			&openapi.ParameterRef{Value: &openapi.Parameter{
				Name: "kind",
				In:   "query",
				Description: "The subjects' kind (User, Client). Absent is \"\", which only bindings without " +
					"subjectKinds admit, as for any kind the host does not know.",
				Schema: openapi.NewSchemaRef("", openapi.NewStringSchema()),
			}},
		},
		Responses: openapi.NewResponses(
			openapi.WithName("200", &openapi.Response{
				Content: openapi.NewContentWithSchema(&openapi.Schema{
					Type: &openapi.Types{openapi.TypeObject},
					Properties: openapi.Schemas{
						"subjects": &openapi.SchemaRef{Value: &openapi.Schema{
							Type:        &openapi.Types{openapi.TypeArray},
							Description: "One entry per requested subject, in request order.",
							Items:       subject,
						}},
					},
				}, []string{"application/json"}),
				Description: new("Every matching binding, per requested subject."),
			}),
			openapi.WithStatus(400, &openapi.ResponseRef{Value: &openapi.Response{
				Description: new("subject missing or empty, more than 32 subjects, a subject over 1024 bytes, or kind repeated"),
			}}),
			openapi.WithStatus(401, &openapi.ResponseRef{Ref: ko.RespRefUnauthorized}),
			openapi.WithStatus(403, &openapi.ResponseRef{Ref: ko.RespRefForbidden}),
		),
		Security: security,
		Summary:  "Resolve subjects against the host's KDexRoleBindings",
		Tags:     []string{"system", "roles", "auth"},
	}
}
