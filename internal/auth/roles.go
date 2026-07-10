package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal"
	"github.com/oasdiff/yaml"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Lookup interface {
	FindInternal(subject string, password string) (bool, jwt.MapClaims, error)
	// ResolveClaims returns a subject's backend claims (e.g. vs_entitlements)
	// WITHOUT a credential check — a password-less lookup the token bridge uses
	// to re-resolve data-driven grants fresh at request time. Returns
	// (nil, nil) when this lookup supplies no such claims. See
	// kdex-tech/host-manager#138.
	ResolveClaims(subject string) (jwt.MapClaims, error)
	Type() string
}

type InternalIdentityProvider interface {
	FindInternal(subject string, password string) (jwt.MapClaims, error)
	FindInternalRolesAndEntitlements(subject string) ([]string, []string, error)
}

type scopeProvider struct {
	Client              client.Client
	Context             context.Context
	ControllerNamespace string
	FocalHost           string

	lookups       []Lookup
	rolesMap      map[string][]string
	exactBindings map[string][]string
	regexBindings []bindingMatcher
}

type bindingMatcher struct {
	re    *regexp.Regexp
	roles []string
}

var _ InternalIdentityProvider = (*scopeProvider)(nil)

func NewRoleProvider(
	ctx context.Context,
	c client.Client,
	focalHost string,
	controllerNamespace string,
	lookups []Lookup,
) (*scopeProvider, error) {
	rc := &scopeProvider{
		Client:              c,
		Context:             ctx,
		ControllerNamespace: controllerNamespace,
		FocalHost:           focalHost,
		lookups:             lookups,
		exactBindings:       make(map[string][]string),
	}

	roles, err := rc.collectRoles()
	if err != nil {
		return nil, err
	}

	rc.rolesMap = rc.buildMappingTable(roles)

	bindings, err := rc.collectBindings()
	if err != nil {
		return nil, err
	}

	// KDexRoleBinding Subject Matching Syntax:
	// 1. Exact Match: Default behavior (e.g., "john.doe").
	// 2. Wildcard Match: "*" matches any subject.
	// 3. Regex Match: Subjects enclosed in slashes (e.g., "/^admin-.*$/") are
	//    treated as Go-style regular expressions.
	for _, b := range bindings.Items {
		sub := b.Spec.Subject
		if sub == "*" {
			// Wildcard match
			re := regexp.MustCompile(".*")
			rc.regexBindings = append(rc.regexBindings, bindingMatcher{re: re, roles: b.Spec.Roles})
		} else if strings.HasPrefix(sub, "/") && strings.HasSuffix(sub, "/") && len(sub) > 2 {
			// Regex match
			re, err := regexp.Compile(sub[1 : len(sub)-1])
			if err != nil {
				// Log error but continue with other bindings
				fmt.Printf("failed to compile regex for binding %s: %v\n", b.Name, err)
				continue
			}
			rc.regexBindings = append(rc.regexBindings, bindingMatcher{re: re, roles: b.Spec.Roles})
		} else {
			// Exact match
			rc.exactBindings[sub] = append(rc.exactBindings[sub], b.Spec.Roles...)
		}
	}

	return rc, nil
}

func (rp *scopeProvider) FindInternal(subject string, password string) (jwt.MapClaims, error) {
	var localIdentity jwt.MapClaims
	for _, lookup := range rp.lookups {
		if ok, identity, err := lookup.FindInternal(subject, password); err != nil {
			return nil, err
		} else if ok {
			localIdentity = identity
			break
		}
	}

	if localIdentity == nil {
		return nil, fmt.Errorf("invalid credentials '%s'", subject)
	}

	subjectForRoles := subject
	if sub, ok := localIdentity["sub"].(string); ok && sub != "" {
		subjectForRoles = sub
	}

	roles, entitlements, err := rp.FindInternalRolesAndEntitlements(subjectForRoles)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve scopes: %w", err)
	}
	localIdentity["roles"] = roles
	localIdentity["entitlements"] = entitlements

	return localIdentity, nil
}

func (rp *scopeProvider) FindInternalRolesAndEntitlements(subject string) ([]string, []string, error) {
	roles := rp.resolveRoles(subject)
	return roles, rp.collectEntitlements(roles), nil
}

// ResolveClaims resolves a subject's backend Lookup claims (e.g.
// vs_entitlements) fresh and password-lessly by asking each configured Lookup,
// merging their results (first writer wins per key). Fail-open: a lookup error
// contributes nothing (never MORE than the subject holds). Returns nil when no
// lookup supplies any claims. See kdex-tech/host-manager#138.
func (rp *scopeProvider) ResolveClaims(subject string) jwt.MapClaims {
	if subject == "" {
		return nil
	}
	var merged jwt.MapClaims
	for _, lookup := range rp.lookups {
		claims, err := lookup.ResolveClaims(subject)
		if err != nil || len(claims) == 0 {
			continue
		}
		if merged == nil {
			merged = jwt.MapClaims{}
		}
		for k, v := range claims {
			if _, exists := merged[k]; !exists {
				merged[k] = v
			}
		}
	}
	return merged
}

func (rp *scopeProvider) collectRoles() (*kdexv1alpha1.KDexRoleList, error) {
	var roles kdexv1alpha1.KDexRoleList
	if err := rp.Client.List(rp.Context, &roles, client.InNamespace(rp.ControllerNamespace), client.MatchingFields{
		internal.HOST_INDEX_KEY: rp.FocalHost,
	}); err != nil {
		return nil, err
	}
	return &roles, nil
}

func (rp *scopeProvider) collectEntitlements(roles []string) []string {
	scopes := make([]string, 0, len(roles))
	for _, role := range roles {
		scopes = append(scopes, rp.rolesMap[role]...)
	}
	return scopes
}

func (rp *scopeProvider) buildMappingTable(roles *kdexv1alpha1.KDexRoleList) map[string][]string {
	table := make(map[string][]string, len(roles.Items))

	for _, role := range roles.Items {
		table[role.Name] = []string{}

		for _, rule := range role.Spec.Rules {
			resourceNames := rule.ResourceNames

			if len(resourceNames) == 0 {
				resourceNames = []string{""}
			}

			for _, resource := range rule.Resources {
				for _, resourceName := range resourceNames {
					for _, verb := range rule.Verbs {
						table[role.Name] = append(table[role.Name], fmt.Sprintf("%s:%s:%s", resource, resourceName, verb))
					}
				}
			}
		}
	}

	return table
}

func (rp *scopeProvider) collectBindings() (*kdexv1alpha1.KDexRoleBindingList, error) {
	var roleBindings kdexv1alpha1.KDexRoleBindingList
	if err := rp.Client.List(rp.Context, &roleBindings, client.InNamespace(rp.ControllerNamespace), client.MatchingFields{
		internal.HOST_INDEX_KEY: rp.FocalHost,
	}); err != nil {
		return nil, err
	}

	return &roleBindings, nil
}

func (rp *scopeProvider) resolveRoles(subject string) []string {
	var roles []string

	// 1. Exact matches (O(1))
	if r, ok := rp.exactBindings[subject]; ok {
		roles = append(roles, r...)
	}

	// 2. Regex/Wildcard matches (O(N))
	for _, bm := range rp.regexBindings {
		if bm.re.MatchString(subject) {
			roles = append(roles, bm.roles...)
		}
	}

	return roles
}

type ldapLookup struct {
	activeDirectory   bool
	addr              string
	attributeMappings map[string]string
	attributeNames    []string
	baseDN            string
	bindUser          string // e.g., "cn=read-only-admin,dc=example,dc=com"
	bindPass          string
	userFilter        string // e.g., "(uid=%s)" or "(sAMAccountName=%s)"
}

var _ Lookup = (*ldapLookup)(nil)

func NewLDAPLookup(secret corev1.Secret) *ldapLookup {
	attributes := map[string]string{
		// default OpenLDAP attribute mappings
		"dn":             "sub",
		"uid":            "preferred_username",
		"cn":             "name",
		"givenName":      "given_name",
		"sn":             "surname",
		"mail":           "email",
		"email_verified": "email_verified",
		"memberOf":       "roles",
	}
	if string(secret.Data["active-directory"]) == TRUE {
		attributes = map[string]string{
			// default Active Directory attribute mappings
			"objectGUID":     "sub",
			"sAMAccountName": "preferred_username",
			"displayName":    "name",
			"givenName":      "given_name",
			"sn":             "surname",
			"mail":           "email",
			"emailVerified":  "email_verified",
			"memberOf":       "roles",
		}
	}
	if secret.Data["attributes"] != nil {
		for attr := range strings.SplitSeq(string(secret.Data["attributes"]), ",") {
			trimmed := strings.TrimSpace(attr)
			if _, ok := attributes[trimmed]; ok {
				continue
			}
			attributes[trimmed] = trimmed
		}
	}
	attributeNames := slices.Collect(maps.Keys(attributes))
	return &ldapLookup{
		addr:              string(secret.Data["addr"]),
		baseDN:            string(secret.Data["base-dn"]),
		bindUser:          string(secret.Data["bind-user"]),
		bindPass:          string(secret.Data["bind-pass"]),
		userFilter:        string(secret.Data["user-filter"]),
		attributeMappings: attributes,
		attributeNames:    attributeNames,
	}
}

func (ll *ldapLookup) FindInternal(subject string, password string) (bool, jwt.MapClaims, error) {
	// 1. Dial on every auth request (or use a pool)
	l, err := ldap.DialURL(ll.addr)
	if err != nil {
		return false, nil, fmt.Errorf("connection error: %w", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			fmt.Printf("connection error: %v\n", err)
		}
	}()

	// 2. Bind with the pre-configured Service Account
	if err := l.Bind(ll.bindUser, ll.bindPass); err != nil {
		return false, nil, fmt.Errorf("service bind failed: %w", err)
	}

	// 3. Search for the user
	searchReq := ldap.NewSearchRequest(
		ll.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(ll.userFilter, ldap.EscapeFilter(subject)),
		ll.attributeNames,
		nil,
	)

	sr, err := l.Search(searchReq)
	if err != nil || len(sr.Entries) != 1 {
		return false, nil, nil
	}

	userEntry := sr.Entries[0]

	// 4. Verify user password
	if err := l.Bind(userEntry.DN, password); err != nil {
		return false, nil, fmt.Errorf("invalid password for subject '%s'", subject)
	}

	current := jwt.MapClaims{}
	for _, attr := range userEntry.Attributes {
		claimName, ok := ll.attributeMappings[attr.Name]
		if !ok {
			continue
		}

		// Special handling for Active Directory binary ID
		if ll.activeDirectory && attr.Name == "objectGUID" {
			raw := userEntry.GetRawAttributeValues("objectGUID")
			if len(raw) > 0 {
				guid, _ := FormatADGUID(raw[0])
				current[claimName] = guid
			}
			continue
		}

		if len(attr.Values) == 1 {
			// Most claims (email, name, sub) should be single strings
			current[claimName] = attr.Values[0]
		} else if len(attr.Values) > 1 {
			// Multi-value attributes (memberOf/roles) stay as slices
			current[claimName] = attr.Values
		}
	}

	return true, current, nil
}

func (ll *ldapLookup) Type() string {
	return "ldap"
}

// ResolveClaims: LDAP supplies no data-driven backend claims. See #138.
func (ll *ldapLookup) ResolveClaims(string) (jwt.MapClaims, error) {
	return nil, nil
}

type secretLookup struct {
	secrets kdexv1alpha1.Secrets
}

var _ Lookup = (*secretLookup)(nil)

func NewSecretLookup(secrets kdexv1alpha1.Secrets) *secretLookup {
	return &secretLookup{
		secrets: secrets.Filter(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "subject" }),
	}
}

// looksLikeBcrypt returns true if the stored secret bytes are in bcrypt
// modular crypt format ($2a$, $2b$, $2x$, $2y$ followed by cost+salt+hash).
// When this is true, the secret MUST be verified through
// bcrypt.CompareHashAndPassword — accepting the hash itself as the
// password (the historical `string(passBytes) == password` shortcut) is
// a credential-bypass primitive for anyone who can read the Secret. See
// kdex-tech/host-manager#47.
func looksLikeBcrypt(b []byte) bool {
	if len(b) < 4 || b[0] != '$' || b[1] != '2' || b[3] != '$' {
		return false
	}
	switch b[2] {
	case 'a', 'b', 'x', 'y':
		return true
	}
	return false
}

func (sl *secretLookup) FindInternal(subject string, password string) (bool, jwt.MapClaims, error) {
	for _, secret := range sl.secrets {
		subBytes, hasSub := secret.Data["sub"]
		emailBytes, hasEmail := secret.Data["email"]
		if (hasSub && string(subBytes) == subject) || (hasEmail && string(emailBytes) == subject) {
			if passBytes, ok := secret.Data["password"]; ok {
				var matched bool
				if looksLikeBcrypt(passBytes) {
					// Bcrypt-stored: the only valid comparison is
					// CompareHashAndPassword. Never accept the hash
					// bytes themselves as the password (#47).
					matched = bcrypt.CompareHashAndPassword(passBytes, []byte(password)) == nil
				} else {
					// Legacy plaintext storage: timing-safe compare.
					matched = subtle.ConstantTimeCompare(passBytes, []byte(password)) == 1
				}
				if matched {
					current := map[string]any{}
					for k, bts := range secret.Data {
						if k == "password" {
							continue
						}
						var v any
						if err := yaml.Unmarshal(bts, &v); err != nil {
							current[k] = string(bts)
						} else {
							current[k] = v
						}
					}
					return true, current, nil
				}
			}
			return false, nil, fmt.Errorf("invalid password for subject/email '%s'", subject)
		}
	}

	return false, nil, nil
}
func (sl *secretLookup) Type() string {
	return "secret"
}

// ResolveClaims: the Secret-backed subject store supplies no data-driven
// backend claims. See #138.
func (sl *secretLookup) ResolveClaims(string) (jwt.MapClaims, error) {
	return nil, nil
}

// FormatADGUID converts the raw binary objectGUID from AD into a standard UUID string.
// AD uses a little-endian format for the first three components.
func FormatADGUID(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("invalid GUID length: %d", len(b))
	}

	// Byte flipping logic to match standard UUID string representation (RFC 4122)
	// AD GUID: [3 2 1 0] [5 4] [7 6] [8 9] [10 11 12 13 14 15]
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15]), nil
}
