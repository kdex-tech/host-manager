package host

import (
	"encoding/json"
	"net/http"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	kdexRolesPath     = "/-/roles"
	kdexRolePath      = "/-/roles/{name}"
	kdexRolesResource = "kdexroles"
	kdexRolesVerb     = "read"
	// kdexRolesItemsKey is the list body's array property (kdexRoleList.Items).
	kdexRolesItemsKey = "items"
)

// kdexRolesHandler exposes the host's KDexRoles -- their rules as stored and the
// entitlements the compiler emits for them, i.e. what a bound subject's token
// carries -- so a companion app can show cluster-defined roles without
// Kubernetes API access or a copy of the role compiler. See
// kdex-tech/host-manager#231.
//
// Each role is gated on its own: kdexroles:<name>:read. The resource is
// "kdexroles", not "roles", because companion apps already use "roles" for
// roles of their own. Bindings are deliberately not exposed: their subjects
// are user identifiers.
func (hh *HostHandler) kdexRolesHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if hh.authChecker == nil {
		return // auth disabled: nothing to gate the listing on
	}
	roles := hh.authExchanger.Roles

	mux.HandleFunc("GET "+kdexRolesPath, func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.GetAuthContext(r.Context()); !ok {
			denial.Write(w, r, denial.Opts{Outcome: denial.Unauthenticated, Issuer: hh.issuerAddress()})
			return
		}
		held := hh.authChecker.GetParsedEntitlements(r.Context())
		none := hh.authChecker.ParseRequirements(nil)

		visible := []auth.RoleInfo{}
		for _, role := range roles() {
			ok, err := hh.authChecker.VerifyResourceParsedEntitlements(kdexRolesResource, role.Name, held, none, kdexRolesVerb)
			if err != nil {
				logf.FromContext(r.Context()).Error(err, "kdexroles authorization check failed", "role", role.Name)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if ok {
				visible = append(visible, role)
			}
		}
		writeKDexRolesJSON(w, kdexRoleList{Items: visible})
	})

	mux.HandleFunc("GET "+kdexRolePath, func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		held := hh.authChecker.GetParsedEntitlements(r.Context())

		// Authorize BEFORE looking the role up, so a denial never tells the
		// caller whether a role of that name exists.
		ok, err := hh.authChecker.VerifyResourceParsedEntitlements(
			kdexRolesResource, name, held, hh.authChecker.ParseRequirements(nil), kdexRolesVerb)
		if err != nil {
			logf.FromContext(r.Context()).Error(err, "kdexroles authorization check failed", "role", name)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if !ok {
			denial.Write(w, r, denial.Opts{
				Outcome: denial.Classify(r.Context(), hh.authChecker, held, kdexRolesResource, name, kdexRolesVerb),
				Issuer:  hh.issuerAddress(),
			})
			return
		}

		for _, role := range roles() {
			if role.Name == name {
				writeKDexRolesJSON(w, role)
				return
			}
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	})

	roleSchema := &openapi.SchemaRef{Value: &openapi.Schema{
		Type: &openapi.Types{openapi.TypeObject},
		Properties: openapi.Schemas{
			"name": openapi.NewSchemaRef("", openapi.NewStringSchema()),
			"rules": &openapi.SchemaRef{Value: &openapi.Schema{
				Type:        &openapi.Types{openapi.TypeArray},
				Description: "The role's PolicyRules as stored on the KDexRole.",
				Items:       &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeObject}}},
			}},
			"entitlements": &openapi.SchemaRef{Value: &openapi.Schema{
				Type:        &openapi.Types{openapi.TypeArray},
				Description: "Exactly the entitlements the host compiles from the rules: what a bound subject's token carries.",
				Items:       openapi.NewSchemaRef("", openapi.NewStringSchema()),
			}},
		},
	}}
	security := &openapi.SecurityRequirements{
		openapi.SecurityRequirement{"bearer": {kdexRolesResource + ":{name}:" + kdexRolesVerb}},
	}
	denied := openapi.WithStatus(401, &openapi.ResponseRef{Ref: ko.RespRefUnauthorized})

	hh.registerPath(kdexRolesPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: kdexRolesPath,
			Paths: map[string]ko.PathItem{
				kdexRolesPath: {
					Description: "Lists the host's KDexRoles the caller may read.",
					Get: &openapi.Operation{
						Description: "Lists the host's KDexRoles with their rules and compiled entitlements. " +
							"Filtered per role: a role is listed only when the caller holds kdexroles:<name>:read " +
							"(kdexroles::read lists every role). An authenticated caller who may read none gets an empty list.",
						OperationID: "kdexroles-list",
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(&openapi.Schema{
									Type: &openapi.Types{openapi.TypeObject},
									Properties: openapi.Schemas{
										kdexRolesItemsKey: &openapi.SchemaRef{Value: &openapi.Schema{
											Type:  &openapi.Types{openapi.TypeArray},
											Items: roleSchema,
										}},
									},
								}, []string{"application/json"}),
								Description: new("The roles the caller may read, sorted by name"),
							}),
							denied,
						),
						Security: security,
						Summary:  "List KDexRoles",
						Tags:     []string{"system", "roles", "auth"},
					},
					Summary: "List the host's KDexRoles",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)

	hh.registerPath(kdexRolePath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: kdexRolePath,
			Paths: map[string]ko.PathItem{
				kdexRolePath: {
					Description: "One of the host's KDexRoles.",
					Get: &openapi.Operation{
						Description: "Returns one KDexRole with its rules and compiled entitlements. Authorization " +
							"is decided before existence, so a denial does not reveal whether the role exists.",
						OperationID: "kdexroles-get",
						Parameters: openapi.Parameters{
							&openapi.ParameterRef{Value: &openapi.Parameter{
								Name:     "name",
								In:       "path",
								Required: true,
								Schema:   openapi.NewSchemaRef("", openapi.NewStringSchema()),
							}},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content:     openapi.NewContentWithSchema(roleSchema.Value, []string{"application/json"}),
								Description: new("The role"),
							}),
							denied,
							openapi.WithStatus(404, &openapi.ResponseRef{Ref: ko.RespRefNotFound}),
						),
						Security: security,
						Summary:  "Get a KDexRole",
						Tags:     []string{"system", "roles", "auth"},
					},
					Summary: "Get one of the host's KDexRoles",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

// kdexRoleList is the GET /-/roles body.
type kdexRoleList struct {
	Items []auth.RoleInfo `json:"items"`
}

// writeKDexRolesJSON writes a per-caller response: the body depends on the
// caller's grants, so it must never be served from a shared cache.
func writeKDexRolesJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(v)
}
