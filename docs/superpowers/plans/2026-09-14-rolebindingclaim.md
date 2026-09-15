# RoleBindingClaim Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `KDexRoleBinding.Subject` match against a configurable, human-authorable claim (e.g. `email`) while the opaque OIDC `sub` remains the stable identity.

**Architecture:** Add two optional fields to the `OIDCProvider` CRD (`roleBindingClaim`, `requireEmailVerified`). In host-manager, resolve a **binding key** distinct from the identity subject at each mint path: `claims[roleBindingClaim]` when it's a non-empty string, else `sub`; when the claim is `email` and verification is required, an unverified `email_verified` falls back to `sub`. Role/binding matching uses the binding key; identity (`sub`) for the token, gate, backend lookup, and refresh lineage is untouched. `sign.Signer.Project` is unchanged — `sub` is never rewritten.

**Tech Stack:** Go 1.26.0, kubebuilder CRDs, testify, envtest.

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-09-14-rolebindingclaim-design.md`

## Global Constraints

- Go version pinned to **1.26.0** across kdex-crds / kdex-host-manager / kdex-nexus-manager.
- **Never** hand-edit the `replace kdex.dev/crds => …` directive to a local path. Propagate via `./updateCrdUsage.sh` from the workspace root.
- Default config must reproduce today's behavior byte-for-byte: `roleBindingClaim` unset ⇒ `"sub"`; `requireEmailVerified` unset ⇒ `true`.
- A CRD serialization change requires releasing **both** host-manager AND nexus-manager, running **each actor's `make test`** (not just `go build`).
- host-manager code work happens on branch `rolebindingclaim`.
- Commit inside the sub-repo where the change lives.

## Cross-repo sequencing (read before starting)

This plan spans two repos. Order matters:

1. **kdex-crds** (Task 1) — add fields, regenerate, verify. Done on kdex-crds `main` (the established workflow; the change is additive/backward-compatible).
2. **Propagation** (Task 2) — from the workspace root, `./updateCrdUsage.sh -t --no-commit` tags kdex-crds and leaves the host-manager/nexus `go.mod` bumps uncommitted; commit the host-manager bump on the `rolebindingclaim` branch. Only after this do the new fields exist for host-manager to compile against.
3. **host-manager** (Tasks 3–7) — on branch `rolebindingclaim`.
4. **Release** (Task 8) — host-manager + nexus.

## File Structure

- `kdex-crds/api/v1alpha1/types.go` — `OIDCProvider` gets `RoleBindingClaim`, `RequireEmailVerified`.
- `kdex-crds/api/v1alpha1/oidcprovider_test.go` — serialization/defaulting assertions for the new fields.
- `kdex-crds/api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/*.yaml`, docs — regenerated (`make generate manifests docs`).
- `kdex-host-manager/internal/auth/config.go` — internal `Config.OIDC` fields + `applyOIDC` mapping.
- `kdex-host-manager/internal/auth/binding_key.go` (new) — `resolveBindingKey` + `emailVerifiedTruthy`.
- `kdex-host-manager/internal/auth/binding_key_test.go` (new) — pure-function table tests.
- `kdex-host-manager/internal/auth/exchange.go` — `subjectSigningContext` signature; `ExchangeToken`, `mintTokensFromCode`, `mintTokensFromSubject` threading; `AuthorizationCodeClaims.IDPClaims`.
- `kdex-host-manager/internal/auth/oauth2.go` — `/-/authorize` handler populates the auth code's IdP-claims snapshot.

---

### Task 1: kdex-crds — add `roleBindingClaim` and `requireEmailVerified`

**Files:**
- Modify: `kdex-crds/api/v1alpha1/types.go` (`OIDCProvider`, ~L843-876)
- Test: `kdex-crds/api/v1alpha1/oidcprovider_test.go`
- Regenerated: `zz_generated.deepcopy.go`, `config/crd/bases/*.yaml`, `docs/`

**Interfaces:**
- Produces: `OIDCProvider.RoleBindingClaim string` (json `roleBindingClaim`, default `"sub"`), `OIDCProvider.RequireEmailVerified *bool` (json `requireEmailVerified`, unset ⇒ true).

- [ ] **Step 1: Write the failing test** — append to `oidcprovider_test.go`:

```go
// TestOIDCProviderRoleBindingClaimSerialization pins the new #<issue> fields:
// the role-binding key claim and the email_verified gate.
func TestOIDCProviderRoleBindingClaimSerialization(t *testing.T) {
	verified := true
	raw, err := json.Marshal(OIDCProvider{
		OIDCProviderURL:      "https://accounts.google.com",
		RoleBindingClaim:     "email",
		RequireEmailVerified: &verified,
	})
	require.NoError(t, err)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Contains(t, got, "roleBindingClaim", "got %s", raw)
	assert.Contains(t, got, "requireEmailVerified", "got %s", raw)

	// Both are optional/omitempty: a bare provider serializes neither.
	rawEmpty, err := json.Marshal(OIDCProvider{OIDCProviderURL: "https://accounts.google.com"})
	require.NoError(t, err)
	var gotEmpty map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rawEmpty, &gotEmpty))
	assert.NotContains(t, gotEmpty, "roleBindingClaim", "unset must omit, got %s", rawEmpty)
	assert.NotContains(t, gotEmpty, "requireEmailVerified", "unset must omit, got %s", rawEmpty)

	// A CR written against the documented keys decodes.
	var decoded OIDCProvider
	require.NoError(t, json.Unmarshal([]byte(`{"roleBindingClaim":"email","requireEmailVerified":false}`), &decoded))
	assert.Equal(t, "email", decoded.RoleBindingClaim)
	require.NotNil(t, decoded.RequireEmailVerified)
	assert.False(t, *decoded.RequireEmailVerified)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-crds && go test ./api/v1alpha1/ -run TestOIDCProviderRoleBindingClaimSerialization -v`
Expected: FAIL (compile error — `RoleBindingClaim`/`RequireEmailVerified` undefined).

- [ ] **Step 3: Add the fields** — in `types.go`, inside `OIDCProvider`, after the `Scopes` field (before the closing brace at ~L876):

```go
	// roleBindingClaim is the OIDC/identity claim whose value KDexRoleBinding.Subject
	// is matched against. Default "sub" preserves matching the opaque provider
	// subject. Set to "email" (with a provider like Google that issues an opaque
	// numeric sub) so operators can author bindings against a human-readable,
	// regex-matchable value (an exact address, or /@acme\.com$/). When the named
	// claim is absent or empty for a login (e.g. a local or PAT credential),
	// matching falls back to "sub".
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="sub"
	// +kubebuilder:validation:MaxLength=256
	RoleBindingClaim string `json:"roleBindingClaim,omitempty" protobuf:"bytes,6,opt,name=roleBindingClaim"`

	// requireEmailVerified gates use of the email claim as the role-binding key on
	// email_verified == true in the login claims. It only has effect when
	// roleBindingClaim == "email". Unset defaults to TRUE (a pointer, so "unset"
	// resolves to the SECURE value rather than Go's zero-value false): an unverified
	// email is a role-authoring key an attacker could assert at a permissive IdP.
	// Google satisfies this automatically. Set explicitly to false only for a
	// trusted enterprise IdP that does not emit email_verified.
	// +kubebuilder:validation:Optional
	RequireEmailVerified *bool `json:"requireEmailVerified,omitempty" protobuf:"varint,7,opt,name=requireEmailVerified"`
```

- [ ] **Step 4: Regenerate deepcopy, manifests, docs**

Run: `cd kdex-crds && make generate manifests docs`
Expected: `zz_generated.deepcopy.go` gains the `*bool` copy for `RequireEmailVerified`; `config/crd/bases/*.yaml` shows the two new properties with `roleBindingClaim` default `sub`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd kdex-crds && go test ./api/v1alpha1/ -run TestOIDCProviderRoleBindingClaimSerialization -v`
Expected: PASS.

- [ ] **Step 6: Full crds verify**

Run: `cd kdex-crds && make test lint`
Expected: PASS (envtest confirms the CRD with the new fields installs).

- [ ] **Step 7: Commit (kdex-crds, main)**

```bash
cd kdex-crds
git add -A
git commit -m "feat: add OIDCProvider.roleBindingClaim + requireEmailVerified

The role-binding key claim (default \"sub\") lets operators author
KDexRoleBinding.Subject against a human-readable claim (e.g. email);
requireEmailVerified (default true) gates the email key on email_verified.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Propagate the CRD tag to host-manager

**Files:**
- Modify (script-driven): `kdex-host-manager/go.mod`, `kdex-host-manager/go.sum` (and `kdex-nexus-manager/go.{mod,sum}`, committed later at release).

**Interfaces:**
- Consumes: Task 1's committed kdex-crds change.
- Produces: host-manager compiling against the new `OIDCProvider` fields.

- [ ] **Step 1: Tag kdex-crds and propagate without auto-committing dependents**

Run: `cd /home/rotty/projects/kdex/workspace && ./updateCrdUsage.sh -t --no-commit`
Expected: runs kdex-crds `make test lint docs`, commits+pushes kdex-crds `main`, tags the new patch version, and leaves `go.mod`/`go.sum` changes in host-manager and nexus **uncommitted**.

- [ ] **Step 2: Ensure the host-manager branch exists and carries the bump**

Run: `cd kdex-host-manager && git rev-parse --abbrev-ref HEAD`
Expected: `rolebindingclaim`. (If not: `git checkout rolebindingclaim`.)

- [ ] **Step 3: Verify host-manager still builds against the new crds tag**

Run: `cd kdex-host-manager && go build ./...`
Expected: builds clean.

- [ ] **Step 4: Commit the go.mod bump (host-manager, rolebindingclaim branch)**

```bash
cd kdex-host-manager
git add go.mod go.sum
git commit -m "chore: bump kdex-crds for roleBindingClaim fields

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

Note: leave the kdex-nexus-manager `go.mod`/`go.sum` changes in its working tree for the release task (Task 8).

---

### Task 3: Binding-key resolver (pure function)

**Files:**
- Create: `kdex-host-manager/internal/auth/binding_key.go`
- Test: `kdex-host-manager/internal/auth/binding_key_test.go`

**Interfaces:**
- Produces: `func resolveBindingKey(claims jwt.MapClaims, sub, roleBindingClaim string, requireEmailVerified bool) string` and `func emailVerifiedTruthy(claims jwt.MapClaims) bool` (package `auth`).

- [ ] **Step 1: Write the failing test** — `binding_key_test.go`:

```go
package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestResolveBindingKey(t *testing.T) {
	const sub = "104187opaque"
	cases := []struct {
		name             string
		claims           jwt.MapClaims
		roleBindingClaim string
		requireVerified  bool
		want             string
	}{
		{"default empty -> sub", jwt.MapClaims{"email": "a@x.io"}, "", true, sub},
		{"explicit sub -> sub", jwt.MapClaims{"email": "a@x.io"}, "sub", true, sub},
		{"email present verified bool", jwt.MapClaims{"email": "a@x.io", "email_verified": true}, "email", true, "a@x.io"},
		{"email present verified string", jwt.MapClaims{"email": "a@x.io", "email_verified": "true"}, "email", true, "a@x.io"},
		{"email unverified bool -> sub", jwt.MapClaims{"email": "a@x.io", "email_verified": false}, "email", true, sub},
		{"email unverified string -> sub", jwt.MapClaims{"email": "a@x.io", "email_verified": "false"}, "email", true, sub},
		{"email verified absent -> sub", jwt.MapClaims{"email": "a@x.io"}, "email", true, sub},
		{"email require off, unverified -> email", jwt.MapClaims{"email": "a@x.io", "email_verified": false}, "email", false, "a@x.io"},
		{"claim absent -> sub", jwt.MapClaims{}, "email", true, sub},
		{"claim empty string -> sub", jwt.MapClaims{"email": ""}, "email", true, sub},
		{"claim non-string -> sub", jwt.MapClaims{"email": 42}, "email", false, sub},
		{"custom claim present", jwt.MapClaims{"upn": "a@x.io"}, "upn", true, "a@x.io"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveBindingKey(tc.claims, sub, tc.roleBindingClaim, tc.requireVerified)
			assert.Equal(t, tc.want, got)
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestResolveBindingKey -v`
Expected: FAIL (compile error — `resolveBindingKey` undefined).

- [ ] **Step 3: Implement** — `binding_key.go`:

```go
package auth

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// resolveBindingKey returns the value KDexRoleBinding.Subject is matched against
// for a login, given the login's claims and the identity subject `sub`. It
// implements the RoleBindingClaim feature: identity stays `sub`, but binding
// matching may key on a configurable, human-authorable claim (e.g. email).
//
//   - roleBindingClaim "" or "sub": always returns sub (historical behavior).
//   - the named claim absent or not a non-empty string: returns sub, so non-OIDC
//     logins (local/PAT) that lack the claim keep matching on sub.
//   - roleBindingClaim == "email" && requireEmailVerified && email_verified not
//     truthy: returns sub, so an unverified address cannot inherit email-keyed roles.
func resolveBindingKey(claims jwt.MapClaims, sub, roleBindingClaim string, requireEmailVerified bool) string {
	if roleBindingClaim == "" || roleBindingClaim == "sub" {
		return sub
	}
	v, ok := claims[roleBindingClaim].(string)
	if !ok || v == "" {
		return sub
	}
	if roleBindingClaim == "email" && requireEmailVerified && !emailVerifiedTruthy(claims) {
		return sub
	}
	return v
}

// emailVerifiedTruthy reports whether the `email_verified` claim asserts a
// verified address. OIDC defines it as a boolean, but some IdPs emit the string
// "true"; both are accepted, everything else (absent, false, "false", other
// types) is treated as unverified.
func emailVerifiedTruthy(claims jwt.MapClaims) bool {
	switch ev := claims["email_verified"].(type) {
	case bool:
		return ev
	case string:
		return strings.EqualFold(ev, "true")
	default:
		return false
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestResolveBindingKey -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd kdex-host-manager
git add internal/auth/binding_key.go internal/auth/binding_key_test.go
git commit -m "feat: add resolveBindingKey for RoleBindingClaim

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Config plumbing (`Config.OIDC` + `applyOIDC`)

**Files:**
- Modify: `kdex-host-manager/internal/auth/config.go` (`Config.OIDC` struct ~L64-73; `applyOIDC` ~L491-501)
- Test: `kdex-host-manager/internal/auth/config_test.go`

**Interfaces:**
- Consumes: Task 2's crds fields (`OIDCProvider.RoleBindingClaim`, `OIDCProvider.RequireEmailVerified`).
- Produces: `Config.OIDC.RoleBindingClaim string`, `Config.OIDC.RequireEmailVerified bool`.

- [ ] **Step 1: Write the failing test** — append to `config_test.go` (follow the file's existing ConfigBuilder/Auth construction pattern; the assertion is the new part):

```go
func TestApplyOIDCRoleBindingClaimDefaults(t *testing.T) {
	// roleBindingClaim unset -> "sub"; requireEmailVerified unset -> true.
	cfg := buildConfigForOIDC(t, &kdexv1alpha1.OIDCProvider{
		OIDCProviderURL: "https://accounts.google.com",
	})
	assert.Equal(t, "sub", cfg.OIDC.RoleBindingClaim)
	assert.True(t, cfg.OIDC.RequireEmailVerified)

	// explicit values honored.
	no := false
	cfg2 := buildConfigForOIDC(t, &kdexv1alpha1.OIDCProvider{
		OIDCProviderURL:      "https://accounts.google.com",
		RoleBindingClaim:     "email",
		RequireEmailVerified: &no,
	})
	assert.Equal(t, "email", cfg2.OIDC.RoleBindingClaim)
	assert.False(t, cfg2.OIDC.RequireEmailVerified)
}
```

Note: implement `buildConfigForOIDC(t, provider)` as a small local helper that constructs a `ConfigBuilder` with a stub `OIDCClientConfigLoader` and an `Issuer`, wraps the provider in an `Auth`, and returns the built `Config`. Mirror the setup already used by the nearest existing OIDC test in `config_test.go`; if none exists, model it on how `applyOIDC`'s dependencies (`OIDCClientConfigLoader`, `Issuer`, `CacheManager`) are set elsewhere in the file's tests.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestApplyOIDCRoleBindingClaimDefaults -v`
Expected: FAIL (compile error — `Config.OIDC.RoleBindingClaim` undefined).

- [ ] **Step 3: Add the internal config fields** — in `config.go`, inside the `OIDC struct` (~L64-73), after `Scopes []string`:

```go
		RoleBindingClaim     string
		RequireEmailVerified bool
```

- [ ] **Step 4: Map them in `applyOIDC`** — in `config.go`, after `cfg.OIDC.Scopes = auth.OIDCProvider.Scopes` (~L501):

```go
	// Default an empty roleBindingClaim to "sub" defensively (belt-and-suspenders
	// with the CRD default) so resolution never keys on an empty claim name.
	cfg.OIDC.RoleBindingClaim = auth.OIDCProvider.RoleBindingClaim
	if cfg.OIDC.RoleBindingClaim == "" {
		cfg.OIDC.RoleBindingClaim = "sub"
	}
	// Unset (nil) resolves to the SECURE default: require email_verified.
	cfg.OIDC.RequireEmailVerified = auth.OIDCProvider.RequireEmailVerified == nil ||
		*auth.OIDCProvider.RequireEmailVerified
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestApplyOIDCRoleBindingClaimDefaults -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd kdex-host-manager
git add internal/auth/config.go internal/auth/config_test.go
git commit -m "feat: plumb roleBindingClaim/requireEmailVerified into Config.OIDC

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Thread the binding key through the OIDC login path (`ExchangeToken`)

**Files:**
- Modify: `kdex-host-manager/internal/auth/exchange.go` (`ExchangeToken` ~L622-669)
- Test: `kdex-host-manager/internal/auth/exchange_test.go` (or the existing OIDC login test file)

**Interfaces:**
- Consumes: `resolveBindingKey` (Task 3); `Config.OIDC.RoleBindingClaim`/`RequireEmailVerified` (Task 4).
- Produces: OIDC login role resolution keyed on the binding key.

- [ ] **Step 1: Write the failing test** — a login test that configures `RoleBindingClaim: "email"` and a `KDexRoleBinding{Subject: "alice@acme.io"}`, drives `ExchangeToken` with a verified id_token for `sub=104187opaque, email=alice@acme.io, email_verified=true`, and asserts the minted access token carries the bound role while `sub` is still `104187opaque`. Model the id_token/verifier stubbing and role-binding fixture on the existing `ExchangeToken` tests in the auth package (e.g. the OIDC refresh/login tests). Assert both:

```go
	// role from the email-keyed binding is present
	assert.Contains(t, accessTokenRoles(t, ts.AccessToken), "acme-admin")
	// identity is still the opaque sub, NOT the email
	assert.Equal(t, "104187opaque", accessTokenSubject(t, ts.AccessToken))
```

(Use whatever token-decoding helpers the existing auth tests use; if none, decode with the package's signer/verifier as those tests do.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestExchangeTokenEmailRoleBinding -v`
Expected: FAIL — no role resolved (bindings are keyed on the opaque sub, which the binding doesn't name).

- [ ] **Step 3: Implement** — in `ExchangeToken`, replace the role resolution at ~L663:

```go
	bindingKey := resolveBindingKey(signingContext, sub, e.config.OIDC.RoleBindingClaim, e.config.OIDC.RequireEmailVerified)
	roles, entitlements, err := e.sp.FindInternalRolesAndEntitlements(bindingKey)
	if err != nil {
		return TokenSet{}, err
	}
```

(`sub` continues to be used for `idpClaimSnapshot`, `GateLogin`, `enrichAfterGate`, and the signed token — do not change those.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestExchangeTokenEmailRoleBinding -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd kdex-host-manager
git add internal/auth/exchange.go internal/auth/exchange_test.go
git commit -m "feat: key OIDC login role resolution on the binding key

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: `subjectSigningContext` signature + refresh path

**Files:**
- Modify: `kdex-host-manager/internal/auth/exchange.go` (`subjectSigningContext` ~L1666; callers `mintTokensFromCode` ~L1792, `mintTokensFromSubject` ~L1876)
- Test: `kdex-host-manager/internal/auth/oidc_refresh_test.go`

**Interfaces:**
- Consumes: `resolveBindingKey` (Task 3).
- Produces: `func (e *Exchanger) subjectSigningContext(subject, bindingKey string) (roles, entitlements []string, backend jwt.MapClaims, err error)` — roles keyed on `bindingKey`, backend claims on `subject`.

- [ ] **Step 1: Write the failing test** — in `oidc_refresh_test.go`, a refresh test where the original OIDC login stored `email`/`email_verified=true` in `RefreshTokenClaims.IDPClaims` and a binding names the email; assert the rotated (refreshed) access token still carries the email-keyed role and `sub` is unchanged. Model on the existing refresh tests in this file.

```go
	assert.Contains(t, accessTokenRoles(t, refreshed.AccessToken), "acme-admin")
	assert.Equal(t, "104187opaque", accessTokenSubject(t, refreshed.AccessToken))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestRefreshEmailRoleBinding -v`
Expected: FAIL — refreshed token lacks the email-keyed role.

- [ ] **Step 3: Change `subjectSigningContext`** — replace ~L1666-1672:

```go
func (e *Exchanger) subjectSigningContext(subject, bindingKey string) (roles, entitlements []string, backend jwt.MapClaims, err error) {
	roles, entitlements, err = e.sp.FindInternalRolesAndEntitlements(bindingKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return roles, entitlements, e.ResolveSubjectClaims(subject), nil
}
```

- [ ] **Step 4: Update `mintTokensFromSubject`** — at ~L1876, compute the binding key from the replayed IdP claims and pass it:

```go
	bindingKey := resolveBindingKey(idpClaims, subject, e.config.OIDC.RoleBindingClaim, e.config.OIDC.RequireEmailVerified)
	roles, entitlements, backend, err := e.subjectSigningContext(subject, bindingKey)
```

- [ ] **Step 5: Update `mintTokensFromCode`** — at ~L1792, pass `claims.Subject` as the binding key for now (no behavior change; Task 7 wires the real key):

```go
	roles, entitlements, backend, err := e.subjectSigningContext(claims.Subject, claims.Subject)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run 'TestRefreshEmailRoleBinding|TestExchangeTokenEmailRoleBinding' -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd kdex-host-manager
git add internal/auth/exchange.go internal/auth/oidc_refresh_test.go
git commit -m "feat: key refresh role resolution on the binding key

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Auth-code carriage of the IdP-claims snapshot

**Files:**
- Modify: `kdex-host-manager/internal/auth/exchange.go` (`AuthorizationCodeClaims` ~L1584; `mintTokensFromCode` ~L1792)
- Modify: `kdex-host-manager/internal/auth/oauth2.go` (authorize handler ~L187-196)
- Test: `kdex-host-manager/internal/auth/exchange_test.go`

**Interfaces:**
- Consumes: `resolveBindingKey` (Task 3); `subjectSigningContext(subject, bindingKey)` (Task 6).
- Produces: `AuthorizationCodeClaims.IDPClaims jwt.MapClaims` (json `idpc`, omitempty).

- [ ] **Step 1: Write the failing test** — an authorization-code round-trip: build a session/authContext carrying `email`/`email_verified=true`, create an auth code via the authorize path (or `CreateAuthorizationCode` with the populated `IDPClaims`), redeem it through `mintTokensFromCode`, and assert the token carries the email-keyed role with `sub` unchanged. Model on existing auth-code tests.

```go
	assert.Contains(t, accessTokenRoles(t, ts.AccessToken), "acme-admin")
	assert.Equal(t, "104187opaque", accessTokenSubject(t, ts.AccessToken))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestAuthCodeEmailRoleBinding -v`
Expected: FAIL — token lacks the email-keyed role (Task 6 left the code path on `claims.Subject`).

- [ ] **Step 3: Add the field** — in `AuthorizationCodeClaims` (~L1584), after `Subject`:

```go
	// IDPClaims is the non-reserved claim snapshot the IdP asserted at login,
	// mirroring RefreshTokenClaims.IDPClaims. It is carried so the code-redemption
	// mint can compute the role-binding key (e.g. email) the same way the login and
	// refresh paths do, without a fresh IdP round-trip. omitempty keeps codes for
	// non-OIDC grants unchanged.
	IDPClaims jwt.MapClaims `json:"idpc,omitempty"`
```

- [ ] **Step 4: Populate it in the authorize handler** — in `oauth2.go`, where `AuthorizationCodeClaims` is built (~L187), add the snapshot from the session's authContext claims:

```go
	claims := AuthorizationCodeClaims{
		AuthMethod:          AuthMethodOAuth2,
		ClientID:            clientId,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		IDPClaims:           idpClaimSnapshot(authCtx.Claims()),
		RedirectURI:         redirectURI,
		Resource:            resource,
		Scope:               scope,
		Subject:             subject,
	}
```

Note: confirm the authContext's claim accessor name while implementing — it is the method that returns the full `jwt.MapClaims` the middleware built from the session token (grep `GetAuthContext`/the authContext type in `internal/auth`). If the accessor differs from `Claims()`, use the actual one; the value needed is the full session claim set (which includes `email`/`email_verified` signed at login).

- [ ] **Step 5: Use it in `mintTokensFromCode`** — replace the Task-6 placeholder at ~L1792:

```go
	bindingKey := resolveBindingKey(claims.IDPClaims, claims.Subject, e.config.OIDC.RoleBindingClaim, e.config.OIDC.RequireEmailVerified)
	roles, entitlements, backend, err := e.subjectSigningContext(claims.Subject, bindingKey)
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestAuthCodeEmailRoleBinding -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd kdex-host-manager
git add internal/auth/exchange.go internal/auth/oauth2.go internal/auth/exchange_test.go
git commit -m "feat: carry IdP-claims snapshot in the auth code for binding-key resolution

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Regression, race, and cross-repo release

**Files:**
- Verify only (host-manager); release kdex-host-manager + kdex-nexus-manager.

**Interfaces:**
- Consumes: all prior tasks.

- [ ] **Step 1: Full host-manager test + race on the auth package**

Run: `cd kdex-host-manager && make test && go test -race ./internal/auth/... ./internal/host/...`
Expected: PASS. This is the regression gate — default-config paths (local/PAT/CI and OIDC without `roleBindingClaim`) must be unchanged, and `-race` covers the lock-scope lesson from the last quad.

- [ ] **Step 2: Lint (workspace root)**

Run: `cd /home/rotty/projects/kdex/workspace && make lint`
Expected: PASS across modules.

- [ ] **Step 3: Push host-manager branch and open PR (user-gated for merge)**

```bash
cd kdex-host-manager
git push -u origin rolebindingclaim
```

Then open a PR (do not merge without the user's go-ahead).

- [ ] **Step 4: Release actors after merge (per crd-schema-change-release-all-actors)**

After host-manager `main` carries the change: tag host-manager; commit the nexus `go.mod` bump left by Task 2, run nexus `make test`, and tag nexus. Deploy is a separate, user-driven infra step.

Run (nexus verification): `cd kdex-nexus-manager && make test`
Expected: PASS (nexus has no code change here, but the CRD bump must not break its tests).

---

## Notes for the executor

- **Out of scope:** host-manager #211 (filtering mapper output vs reserved claims in `sign.Signer.Project`). This plan never rewrites `sub`, so #211 is neither needed nor closed.
- Line numbers are approximate (`~L…`) — locate by symbol, not by line.
- If any test-helper name in Tasks 5–7 (`accessTokenRoles`, `accessTokenSubject`, id_token stubbing, role-binding fixtures) does not already exist, build it by copying the nearest existing auth-package test's approach rather than inventing a new harness.
