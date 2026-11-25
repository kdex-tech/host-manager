package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	openapi "github.com/getkin/kin-openapi/openapi3"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	kdexRolesPath = "/-/roles"
	kdexRolePath  = "/-/roles/{name}"
	// rolesResource is the kdex-roles contract's resource: roles:<name>:read
	// reads one role, roles::read every role.
	rolesResource = "roles"
	// legacyRolesResource is the deprecated alias kdexroles:<name>:read,
	// accepted for one release (#303).
	//
	// TODO(#304, v0.36.0): remove the kdexroles alias. Delete:
	// legacyRolesResource, legacyRoleGrantNote, maxLegacyRoleGrantCallers,
	// noLegacySubjectKey, subjectHash, noteLegacyRoleGrant,
	// legacyRoleGrantCallers, the legacy branch of canReadRole (and its
	// legacyOnly result) and both handlers' legacyOnly handling, the
	// HostHandler fields legacyRoleGrantMu, legacyRoleGrantLogged and
	// legacyRoleGrantSuppressed, the "deprecated" sentence of both /-/roles
	// operations, and the kdexroles cases in kdexroles_test.go.
	legacyRolesResource = "kdexroles"
	rolesVerb           = "read"
	// kdexRolesItemsKey is the list body's array property (kdexRoleList.Items).
	kdexRolesItemsKey = "items"

	// maxLegacyRoleGrantCallers bounds the deprecation log-once set; past it
	// one line says further callers are suppressed.
	maxLegacyRoleGrantCallers = 1024
	// noLegacySubjectKey is the one log-once key of every context that names
	// no subject.
	noLegacySubjectKey = "no-subject"
)

// roleReadChecker is the part of the host's authorization checker the role
// gate uses.
type roleReadChecker interface {
	ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements
	VerifyResourceParsedEntitlements(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error)
}

// canReadRole reports whether a caller holding held may read the role named
// name, and whether only the deprecated kdexroles grant admitted it. none is
// checker.ParseRequirements(nil), parsed once by the caller.
func canReadRole(checker roleReadChecker, held entitlements.ParsedEntitlements, none entitlements.ParsedRequirements, name string) (ok, legacyOnly bool, err error) {
	if ok, err := checker.VerifyResourceParsedEntitlements(rolesResource, name, held, none, rolesVerb); err != nil || ok {
		return ok, false, err
	}
	ok, err = checker.VerifyResourceParsedEntitlements(legacyRolesResource, name, held, none, rolesVerb)
	return ok, ok, err
}

// noteLegacyRoleGrant logs, once per host per caller, that a role was read on
// the deprecated kdexroles grant alone, so the operator can find and migrate
// every such grant without the log growing with traffic. The set lives on the
// HostHandler, keyed by host and subject; every context naming no subject
// shares one key; and it holds at most maxLegacyRoleGrantCallers callers,
// after which one line says further callers are suppressed. role must name a
// role that exists, never a caller-chosen name. The caller is logged as
// subjectHash, not its raw subject.
func (hh *HostHandler) noteLegacyRoleGrant(ctx context.Context, role string) {
	subject := ""
	if ac, ok := auth.GetAuthContext(ctx); ok {
		subject, _ = ac.GetSubject()
	}
	caller := noLegacySubjectKey
	if subject != "" {
		caller = subjectHash(subject)
	}
	key := hh.Name + "\x00" + caller

	hh.legacyRoleGrantMu.Lock()
	if _, seen := hh.legacyRoleGrantLogged[key]; seen {
		hh.legacyRoleGrantMu.Unlock()
		return
	}
	if len(hh.legacyRoleGrantLogged) >= maxLegacyRoleGrantCallers {
		first := !hh.legacyRoleGrantSuppressed
		hh.legacyRoleGrantSuppressed = true
		hh.legacyRoleGrantMu.Unlock()
		if first {
			hh.log.Info("further deprecated-grant callers suppressed; grant roles:<name>:read instead "+
				"(kdexroles removed in v0.36.0, kdex-tech/host-manager#304)",
				"host", hh.Name, "logged", maxLegacyRoleGrantCallers)
		}
		return
	}
	if hh.legacyRoleGrantLogged == nil {
		hh.legacyRoleGrantLogged = map[string]struct{}{}
	}
	hh.legacyRoleGrantLogged[key] = struct{}{}
	hh.legacyRoleGrantMu.Unlock()

	hh.log.Info("deprecated kdexroles entitlement used; grant roles:<name>:read instead "+
		"(removed in v0.36.0, kdex-tech/host-manager#304)",
		"host", hh.Name, "subjectHash", caller, "role", role,
		"grant", legacyRolesResource+":"+role+":"+rolesVerb, "replacement", rolesResource+":"+role+":"+rolesVerb)
}

// legacyRoleGrantCallers is the size of the deprecation log-once set.
func (hh *HostHandler) legacyRoleGrantCallers() int {
	hh.legacyRoleGrantMu.Lock()
	defer hh.legacyRoleGrantMu.Unlock()
	return len(hh.legacyRoleGrantLogged)
}

// subjectHash names a caller in a log line without its raw subject: the
// first 12 hex digits of its SHA-256.
func subjectHash(subject string) string {
	h := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(h[:])[:12]
}

// kdexRolesHandler exposes the host's KDexRoles -- their rules as stored and the
// entitlements the compiler emits for them, i.e. what a bound subject's token
// carries -- so a companion app can show cluster-defined roles without
// Kubernetes API access or a copy of the role compiler. See
// kdex-tech/host-manager#231.
//
// Each role is gated on its own: roles:<name>:read. The resource is "roles",
// unified with the kdex-roles contract (the vocabulary the role service and
// eum implement: roles:{key}:read|update|delete|assign), so a KDexRole and an
// app's custom role share one key space: KDexRoles are the contract's
// built-in, statically bound roles. kdexroles:<name>:read is a deprecated
// alias, accepted for one release and logged when it alone admits a role
// (#303). Bindings, whose subjects are user identifiers, are not listed
// here: GET /-/rolebindings resolves subjects against them, gated on the
// contract's role_assignments_read scope.
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
			ok, legacyOnly, err := canReadRole(hh.authChecker, held, none, role.Name)
			if err != nil {
				logf.FromContext(r.Context()).Error(err, "roles authorization check failed", "role", role.Name)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if ok {
				visible = append(visible, role)
			}
			if legacyOnly {
				hh.noteLegacyRoleGrant(r.Context(), role.Name)
			}
		}
		writeKDexRolesJSON(w, kdexRoleList{Items: visible})
	})

	mux.HandleFunc("GET "+kdexRolePath, func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		held := hh.authChecker.GetParsedEntitlements(r.Context())

		// Authorize BEFORE looking the role up, so a denial never tells the
		// caller whether a role of that name exists.
		ok, legacyOnly, err := canReadRole(hh.authChecker, held, hh.authChecker.ParseRequirements(nil), name)
		if err != nil {
			logf.FromContext(r.Context()).Error(err, "roles authorization check failed", "role", name)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if !ok {
			denial.Write(w, r, denial.Opts{
				Outcome: denial.Classify(r.Context(), hh.authChecker, held, rolesResource, name, rolesVerb),
				Issuer:  hh.issuerAddress(),
			})
			return
		}
		for _, role := range roles() {
			if role.Name == name {
				// Noted only once the role is found, so no caller-chosen
				// name reaches the log-once set or the log.
				if legacyOnly {
					hh.noteLegacyRoleGrant(r.Context(), name)
				}
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
		openapi.SecurityRequirement{"bearer": {rolesResource + ":{name}:" + rolesVerb}},
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
							"Filtered per role: a role is listed only when the caller holds roles:<name>:read " +
							"(roles::read lists every role), the kdex-roles contract's grant: KDexRole names share " +
							"one key space with an app's custom roles. " + legacyRoleGrantNote +
							" An authenticated caller who may read none gets an empty list.",
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
						Description: "Returns one KDexRole with its rules and compiled entitlements. Requires " +
							"roles:<name>:read. " + legacyRoleGrantNote + " Authorization " +
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
							openapi.WithStatus(403, &openapi.ResponseRef{Ref: ko.RespRefForbidden}),
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

// legacyRoleGrantNote names the deprecated alias in both operations' text.
const legacyRoleGrantNote = "The legacy kdexroles:<name>:read is a deprecated alias, accepted until v0.36.0 " +
	"(kdex-tech/host-manager#304)."

// kdexRoleList is the GET /-/roles body.
type kdexRoleList struct {
	Items []auth.RoleInfo `json:"items"`
}

// writeKDexRolesJSON writes a per-caller response: the body depends on the
// caller's grants, so it must never be served from a shared cache.
func writeKDexRolesJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", noStoreCacheControl)
	_ = json.NewEncoder(w).Encode(v)
}
