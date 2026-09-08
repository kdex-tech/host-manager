# FAT Token Exchange Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a `KDexFunction` handler trade its inbound Function Access Token (FAT) for a host-signed JWT addressed to another function's audience, so it can call that function directly in-cluster.

**Architecture:** Add an RFC 8693 token-exchange grant to the host token endpoint (`/-/token`). The handler presents its inbound FAT as `subject_token` (the FAT itself authenticates the call — no client secret). host-manager verifies the FAT, re-resolves the subject's entitlements, and mints a fresh JWT whose `aud` is the target function's audience, resolved from an **internal-inclusive** basePath→audience map. fngogen is extended to (a) expose the raw inbound token to handlers via context and (b) ship an `Exchange()` helper that performs the round-trip.

**Tech Stack:** Go 1.26.0; `github.com/golang-jwt/jwt/v5`; the existing `internal/sign` signer, `internal/auth` Exchanger/OAuth2, and `internal/host` HostHandler; fngogen Go templates (`text/template`).

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-09-07-fat-token-exchange-design.md`

## Global Constraints

- **Go is pinned to 1.26.0** across kdex-crds / host-manager / nexus-manager — do not change `go.mod` Go versions.
- **No `kdex-crds` change.** This feature ships as a host-manager release + an fngogen release. If you find yourself editing a CRD type, stop — the design forbids it.
- **Grant type URN (verbatim):** `urn:ietf:params:oauth:grant-type:token-exchange`. **Subject token type (verbatim):** `urn:ietf:params:oauth:token-type:access_token`.
- **The token-exchange grant is clientless** — it is authenticated by the `subject_token`, not by `client_id`/`client_secret`. It MUST be handled before the client-authentication block in `OAuth2TokenHandler`.
- **The minted token's `aud` is authoritative from a per-target signer.** `sign.Signer` bakes `audience` at construction (`internal/sign/sign.go:142-168`); mint with a fresh `sign.NewSigner(targetAudience, …)`, never by mutating an existing signer.
- **Entitlements are re-resolved from the subject's roles** (`Exchanger.ResolveInternalRolesAndEntitlements`), not copied from the subject_token.
- **Target resolution is internal-inclusive:** a `spec.internal: true` function must resolve. Do NOT reuse `oauth2ProtectedResources()` / `oauth2ResourceAudiences()` — they skip `fn.Spec.Internal`.
- **Run `make test` in each repo** (not just `go build`) before declaring a task done — the host-manager module's envtest catches wiring/validation regressions a build misses.
- **Commit inside the sub-repo** where the change lives. host-manager work is on branch `feat/fat-token-exchange` (already created); create a matching branch in fngogen before its first commit.

---

### Task 1: Internal-inclusive target resolver + OAuth2 wiring

**Files:**
- Modify: `kdex-host-manager/internal/host/oauth2_resources.go`
- Test: `kdex-host-manager/internal/host/oauth2_resources_test.go`
- Modify: `kdex-host-manager/internal/auth/oauth2.go:20-25` (add the `ExchangeTargets` field to the `OAuth2` struct, beside `ResourceAudiences`)
- Modify: the site where `OAuth2{…ResourceAudiences: …}` (or the auth `Config`) is populated from the host — find it with `rg -n "ResourceAudiences:" internal/` (it is fed the `oauth2ResourceAudiences()` snapshot; add `ExchangeTargets: hh.exchangeTargetAudiences()` at the same site).

**Interfaces:**
- Produces: `func (hh *HostHandler) exchangeTargetAudiences() map[string]string` — maps both `basePath` and `issuer+basePath` → `fatAudienceFor(fn)` for every **Ready** function on the host, **including `Spec.Internal`**. Also: a new exported field `ExchangeTargets map[string]string` on `auth.OAuth2`.

- [ ] **Step 1: Write the failing test** (`internal/host/oauth2_resources_test.go`)

```go
func TestExchangeTargetAudiences_IncludesInternal(t *testing.T) {
	hh := &HostHandler{
		host:   kdexv1alpha1.KDexHost{ /* minimal; issuer resolves via issuerAddressLocked */ },
		scheme: "https",
		functions: []kdexv1alpha1.KDexFunction{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "public-fn"},
				Spec:       kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/v1/public"}},
				Status:     kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady, URL: "https://public-fn.ns.svc.cluster.local"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "internal-fn"},
				Spec:       kdexv1alpha1.KDexFunctionSpec{Internal: true, API: kdexv1alpha1.API{BasePath: "/v1/internal"}},
				Status:     kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady, URL: "https://internal-fn.ns.svc.cluster.local"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pending-fn"},
				Spec:       kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/v1/pending"}},
				Status:     kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStatePending, URL: "https://pending-fn.ns.svc.cluster.local"},
			},
		},
	}

	got := hh.exchangeTargetAudiences()

	// internal function resolves by basePath -> its cluster-local audience
	assert.Equal(t, "https://internal-fn.ns.svc.cluster.local", got["/v1/internal"])
	// public function too
	assert.Equal(t, "https://public-fn.ns.svc.cluster.local", got["/v1/public"])
	// pending function is excluded
	_, ok := got["/v1/pending"]
	assert.False(t, ok, "non-Ready functions must not be resolvable targets")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestExchangeTargetAudiences_IncludesInternal -v`
Expected: FAIL — `hh.exchangeTargetAudiences` undefined.

- [ ] **Step 3: Implement the resolver** (append to `internal/host/oauth2_resources.go`)

```go
// exchangeTargetAudiences maps a token-exchange `resource` value to the target
// function's minted audience. Unlike oauth2ProtectedResources, it includes
// spec.Internal functions (the primary direct B-to-B targets) and does NOT
// require oauth2 protection — a token-exchange target only needs a resolvable
// audience, which every Ready function has. Both the basePath and the full
// issuer+basePath form are keys so a caller may send either as `resource`.
// The mapped value is fatAudienceFor(fn), the single source of truth the proxy
// FAT mint also uses, so exchange-minted and proxy-minted audiences never drift.
//
// Caller must hold hh.mu: it reads hh.functions and (via issuerAddressLocked)
// hh.host and hh.scheme.
func (hh *HostHandler) exchangeTargetAudiences() map[string]string {
	out := map[string]string{}
	issuer := hh.issuerAddressLocked()
	if issuer == "" {
		return out
	}
	for i := range hh.functions {
		fn := &hh.functions[i]
		if fn.Status.State != kdexv1alpha1.KDexFunctionStateReady {
			continue
		}
		aud := fatAudienceFor(fn)
		if aud == "" {
			continue
		}
		out[fn.Spec.API.BasePath] = aud
		out[issuer+fn.Spec.API.BasePath] = aud
	}
	return out
}
```

- [ ] **Step 4: Add the `ExchangeTargets` field to `auth.OAuth2`** (`internal/auth/oauth2.go`, beside `ResourceAudiences`)

```go
	// ExchangeTargets maps a token-exchange `resource` value (basePath or
	// issuer+basePath) to the target function's audience. Includes internal
	// functions. Snapshot handed in by the host, same pattern as
	// ResourceAudiences.
	ExchangeTargets map[string]string
```

- [ ] **Step 5: Wire the snapshot** at the site found via `rg -n "ResourceAudiences:" internal/` — add alongside it:

```go
		ExchangeTargets: hh.exchangeTargetAudiences(),
```

- [ ] **Step 6: Run tests**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestExchangeTargetAudiences_IncludesInternal -v && go build ./...`
Expected: PASS and clean build.

- [ ] **Step 7: Commit**

```bash
cd kdex-host-manager
git add internal/host/oauth2_resources.go internal/host/oauth2_resources_test.go internal/auth/oauth2.go
git commit -m "feat(auth): internal-inclusive token-exchange target resolver

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `Exchanger.ExchangeSubjectToken` + `act` in the projection allowlist

**Files:**
- Modify: `kdex-host-manager/internal/sign/sign.go:174` (add `"act"` to the projected-claims allowlist)
- Modify: `kdex-host-manager/internal/auth/exchange.go` (new method)
- Test: `kdex-host-manager/internal/auth/exchange_tokenexchange_test.go`

**Interfaces:**
- Consumes: `Config.ActivePair` (`*keys.KeyPair`, has `.Private`, `.KeyId`), `Config.Issuer` (string), `Config.TokenTTL` (time.Duration), `Exchanger.ResolveInternalRolesAndEntitlements(subject string) ([]string, []string, error)`, `sign.NewSigner`.
- Produces: `func (e *Exchanger) ExchangeSubjectToken(subjectToken, targetAudience string) (TokenSet, error)` — verifies the subject_token is a host-signed, unexpired JWT with `iss = Config.Issuer` (audience NOT checked — a FAT's aud is a function), extracts `sub`, re-resolves entitlements, and mints a JWT for `targetAudience` carrying `sub`, `entitlements`, `roles`, and an `act` claim `{"sub": <subject_token aud>}`. Returns `TokenSet{AccessToken, Subject, Scope:""}`.

- [ ] **Step 1: Add `"act"` to the projection allowlist** (`internal/sign/sign.go:174`)

```go
	for _, claim := range []string{"email", "entitlements", "idp", "roles", "scope", "scp", "grant_type", "act"} {
```

- [ ] **Step 2: Write the failing test** (`internal/auth/exchange_tokenexchange_test.go`)

Build a signer over a P-256 key, mint a FAT (aud="https://fn-a.svc", sub="alice"), then exchange it. Use an Exchanger whose identity provider returns a known entitlement for "alice".

```go
func TestExchangeSubjectToken_MintsForTargetAudienceWithReResolvedEntitlements(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	// A FAT the handler would hold: aud = function A, sub = alice, iss = host.
	fatSigner, err := sign.NewSigner("https://fn-a.ns.svc.cluster.local", time.Hour, "https://host.example", &cs, "kid-1", nil)
	require.NoError(t, err)
	fat, err := fatSigner.Sign(jwt.MapClaims{"sub": "alice", "entitlements": []string{"stale:from:fat"}})
	require.NoError(t, err)

	e := newTestExchanger(t, &cs, "kid-1", "https://host.example") // resolver returns ents ["functions:/v1/internal:read"] for "alice"

	ts, err := e.ExchangeSubjectToken(fat, "https://fn-b.ns.svc.cluster.local")
	require.NoError(t, err)
	require.Equal(t, "alice", ts.Subject)

	claims := parseClaims(t, ts.AccessToken, &cs) // helper: jwt.Parse with the public key, no aud filter
	assert.Equal(t, []any{"https://fn-b.ns.svc.cluster.local"}, claims["aud"])
	assert.Equal(t, "https://host.example", claims["iss"])
	// entitlements were RE-RESOLVED from roles, not copied from the FAT
	assert.Contains(t, claims["entitlements"], "functions:/v1/internal:read")
	assert.NotContains(t, claims["entitlements"], "stale:from:fat")
	// act records the calling function (the FAT's audience)
	act, _ := claims["act"].(map[string]any)
	assert.Equal(t, "https://fn-a.ns.svc.cluster.local", act["sub"])
}

func TestExchangeSubjectToken_RejectsForgedOrExpiredOrSubjectless(t *testing.T) {
	// (a) forged: signed by a DIFFERENT key -> error
	// (b) expired: NewSigner with a negative/zero-elapsed exp -> error
	// (c) no sub in subject_token -> error
	// Each asserts err != nil and empty AccessToken.
}
```

(Write `newTestExchanger`, `parseClaims` as small local helpers in this test file; mirror the fixtures in `internal/auth/exchange_resource_test.go` for the identity-provider stub.)

- [ ] **Step 3: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestExchangeSubjectToken -v`
Expected: FAIL — `ExchangeSubjectToken` undefined.

- [ ] **Step 4: Implement the method** (`internal/auth/exchange.go`)

```go
// ExchangeSubjectToken performs an RFC 8693 token exchange: it verifies a
// host-issued subject_token (a FAT), re-resolves the subject's entitlements,
// and mints a fresh JWT addressed to targetAudience. The subject_token's
// audience is intentionally NOT checked -- a FAT's aud is a function, not the
// host -- but its signature, issuer and expiry are. The minted token carries
// the subject's re-resolved entitlements (never the subject_token's), so the
// target function's own entitlement checks remain authoritative. An `act` claim
// records the calling function (the subject_token's audience) for audit.
func (e *Exchanger) ExchangeSubjectToken(subjectToken, targetAudience string) (TokenSet, error) {
	if e == nil || !e.config.IsAuthEnabled() {
		return TokenSet{}, fmt.Errorf("%w: auth not enabled", ErrServerError)
	}
	if e.config.ActivePair == nil {
		return TokenSet{}, fmt.Errorf("%w: no active key pair", ErrServerError)
	}

	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(
		subjectToken, claims,
		func(*jwt.Token) (any, error) { return e.config.ActivePair.Private.Public(), nil },
		jwt.WithIssuer(e.config.Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !tok.Valid {
		return TokenSet{}, fmt.Errorf("invalid subject_token: %w", err)
	}

	sub, _ := claims.GetSubject()
	if sub == "" {
		return TokenSet{}, fmt.Errorf("subject_token has no subject")
	}

	// The calling function is the subject_token's audience (the FAT aud).
	actorAud := ""
	if auds, aerr := claims.GetAudience(); aerr == nil && len(auds) > 0 {
		actorAud = auds[0]
	}

	roles, ents, rerr := e.ResolveInternalRolesAndEntitlements(sub)
	if rerr != nil {
		return TokenSet{}, fmt.Errorf("%w: failed to resolve entitlements for %s: %v", ErrServerError, sub, rerr)
	}

	signer, err := sign.NewSigner(
		targetAudience,
		e.config.TokenTTL,
		e.config.Issuer,
		&e.config.ActivePair.Private,
		e.config.ActivePair.KeyId,
		nil,
	)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: failed to build signer for %s: %v", ErrServerError, targetAudience, err)
	}

	signingContext := jwt.MapClaims{
		"sub":          sub,
		"roles":        roles,
		"entitlements": ents,
	}
	if actorAud != "" {
		signingContext["act"] = map[string]any{"sub": actorAud}
	}

	accessToken, err := signer.Sign(signingContext)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: failed to sign exchanged token: %v", ErrServerError, err)
	}

	return TokenSet{AccessToken: accessToken, Subject: sub}, nil
}
```

- [ ] **Step 5: Run tests**

Run: `cd kdex-host-manager && go test ./internal/auth/ ./internal/sign/ -run 'TestExchangeSubjectToken|TestProject' -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd kdex-host-manager
git add internal/sign/sign.go internal/auth/exchange.go internal/auth/exchange_tokenexchange_test.go
git commit -m "feat(auth): ExchangeSubjectToken (RFC 8693) + act in projection allowlist

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Token-exchange grant branch in `OAuth2TokenHandler` + discovery

**Files:**
- Modify: `kdex-host-manager/internal/auth/oauth2.go` (`OAuth2TokenHandler`, add the clientless branch near the top)
- Modify: `kdex-host-manager/internal/auth/discovery.go:66-71` (advertise the grant)
- Test: `kdex-host-manager/internal/auth/oauth2_tokenexchange_test.go`, `internal/auth/discovery_test.go`

**Interfaces:**
- Consumes: `OAuth2.ExchangeTargets` (Task 1), `Exchanger.ExchangeSubjectToken` (Task 2), `writeTokenResponse`/`writeOAuthError` (existing in `oauth2.go`).
- Produces: `/-/token` handling of `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.

- [ ] **Step 1: Write the failing handler test** (`internal/auth/oauth2_tokenexchange_test.go`)

```go
func TestTokenHandler_TokenExchange_InternalTarget(t *testing.T) {
	o := newTestOAuth2(t) // wires ExchangeTargets{"/v1/internal": "https://fn-b.ns.svc.cluster.local"} + a host key
	fat := mintTestFAT(t, o, "alice", "https://fn-a.ns.svc.cluster.local")

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {fat},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"/v1/internal"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/-/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	o.OAuth2TokenHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp TokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	claims := parseClaims(t, resp.AccessToken, o.testKey(t))
	assert.Equal(t, []any{"https://fn-b.ns.svc.cluster.local"}, claims["aud"])
}

func TestTokenHandler_TokenExchange_UnknownResourceIsInvalidTarget(t *testing.T) {
	// resource "/v1/does-not-exist" -> HTTP 400, error "invalid_target"
}

func TestTokenHandler_TokenExchange_NoClientRequired(t *testing.T) {
	// same as the happy path but with NO client_id/client_secret in the form -> 200
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestTokenHandler_TokenExchange -v`
Expected: FAIL — grant returns `unsupported_grant_type` / 400.

- [ ] **Step 3: Implement the clientless branch** — at the very top of `OAuth2TokenHandler`, after parsing the form but BEFORE the client-authentication block (client_id resolution), insert:

```go
	if r.FormValue("grant_type") == GRANT_TYPE_TOKEN_EXCHANGE {
		o.handleTokenExchange(w, r)
		return
	}
```

Add the constant beside the other `GRANT_TYPE_*` (search `rg -n "GRANT_TYPE_REFRESH_TOKEN =" internal/auth`):

```go
	GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
```

Add the handler:

```go
// handleTokenExchange implements the RFC 8693 token-exchange grant. It is
// clientless: the subject_token (a host-issued FAT) is the authentication, so
// this path deliberately runs before OAuth2TokenHandler's client-auth block.
func (o *OAuth2) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	subjectToken := r.FormValue("subject_token")
	subjectTokenType := r.FormValue("subject_token_type")
	resource := r.FormValue("resource")

	if subjectToken == "" || resource == "" {
		writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "subject_token and resource are required")
		return
	}
	// Accept the access_token subject type (JWT). Reject others explicitly.
	if subjectTokenType != "" && subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "unsupported subject_token_type")
		return
	}

	targetAudience, ok := o.ExchangeTargets[resource]
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, errCodeInvalidTarget, "unknown resource")
		return
	}

	ts, err := o.AuthExchanger.ExchangeSubjectToken(subjectToken, targetAudience)
	if err != nil {
		// Subject-token faults are the client's; resolver/signer faults are ours.
		if errors.Is(err, ErrServerError) {
			writeOAuthError(w, http.StatusInternalServerError, errCodeServerError, genericServerErrorDescription)
			return
		}
		writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid subject_token")
		return
	}

	resp := TokenResponse{
		AccessToken:     ts.AccessToken,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
		ExpiresIn:       int(o.AccessTokenTTL.Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errCodeServerError, genericServerErrorDescription)
	}
}
```

Add `errCodeInvalidTarget = "invalid_target"` to `internal/auth/oautherr.go` (beside `errCodeUnsupportedGrantType`), and add an `IssuedTokenType` field to `TokenResponse` if not present (`json:"issued_token_type,omitempty"`). Confirm `o.AuthExchanger` is the field name the OAuth2 struct uses for its `*Exchanger` (search `rg -n "Exchanger" internal/auth/oauth2.go`).

- [ ] **Step 4: Advertise the grant** (`internal/auth/discovery.go:66-71`)

```go
		GrantTypesSupported: []string{
			"authorization_code",
			"client_credentials",
			"password",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},
```

Update the discovery test to assert the new entry.

- [ ] **Step 5: Run tests**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run 'TestTokenHandler_TokenExchange|Discovery' -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd kdex-host-manager
git add internal/auth/oauth2.go internal/auth/discovery.go internal/auth/oautherr.go internal/auth/oauth2_tokenexchange_test.go internal/auth/discovery_test.go
git commit -m "feat(auth): RFC 8693 token-exchange grant at /-/token

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: fngogen — flow the raw inbound token to handlers via context

**Files:**
- Modify: `kdex-fngogen/cmd/templates/main.go.tmpl` (context key + accessor + stash in the security handlers)
- Test: `kdex-fngogen/cmd/main_test.go` (golden/generation assertion)
- Regenerate: any committed fixtures under `kdex-fngogen/test-fixtures/` affected by the template change.

**Interfaces:**
- Produces (in every generated function's `main` package): `RequestTokenContextKey ContextKey`, `func RequestTokenFromContext(ctx context.Context) (string, bool)`, and — for the `bearer`/`oauth2`/`oidc` handlers — the raw token stashed in the returned context. Handlers/`Exchange()` consume `RequestTokenFromContext`.

- [ ] **Step 1: Write the failing generation test** (`kdex-fngogen/cmd/main_test.go`)

Add an assertion to the existing bearer-security generation case (or a new subtest) that the generated `main.go` contains the accessor and stashes the raw token:

```go
func TestGenerate_BearerHandlerFlowsRawToken(t *testing.T) {
	out := generateForFixture(t, "openapi-spec-bearer.json") // reuse an existing bearer fixture helper
	assert.Contains(t, out, "RequestTokenContextKey ContextKey")
	assert.Contains(t, out, "func RequestTokenFromContext(ctx context.Context) (string, bool)")
	// HandleBearer must put the raw token into the context it returns
	assert.Contains(t, out, "context.WithValue(ctx, RequestTokenContextKey, t.Token)")
}
```

(If there is no bearer fixture + `generateForFixture` helper, mirror the existing content-less fixture test added for #3 in `cmd/main_test.go`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-fngogen && go test ./cmd/ -run TestGenerate_BearerHandlerFlowsRawToken -v`
Expected: FAIL — strings absent.

- [ ] **Step 3: Edit the template** (`cmd/templates/main.go.tmpl`)

Extend the context-key block (currently `UserContextKey ContextKey = "user"`):

```go
const (
	UserContextKey         ContextKey = "user"
	RequestTokenContextKey ContextKey = "request-token"
)

// RequestTokenFromContext returns the raw inbound bearer token carried on the
// request, for handlers that need to exchange it for a token addressed to
// another function (RFC 8693 token exchange via the host /-/token endpoint).
func RequestTokenFromContext(ctx context.Context) (string, bool) {
	tok, ok := ctx.Value(RequestTokenContextKey).(string)
	return tok, ok
}
```

Stash the raw token in the JWT-bearing handlers. For `HandleBearer`:

```go
func (s *security) HandleBearer(ctx context.Context, operationName api.OperationName, t api.Bearer) (context.Context, error) {
	token, err := jwt.Parse(t.Token, s.jwks.Keyfunc, jwt.WithAudience(s.audience), jwt.WithIssuer(s.issuer))
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	ctx = context.WithValue(ctx, RequestTokenContextKey, t.Token)
	return s.hasValidClaims(ctx, "entitlements", "bearer", t.Roles, token.Claims.(jwt.MapClaims))
}
```

Apply the identical `ctx = context.WithValue(ctx, RequestTokenContextKey, t.Token)` line (immediately before the `return s.hasValidClaims(...)`) to `HandleOAuth2` and `HandleOpenIdConnect`. (Leave the apiKey/PASETO handlers unchanged — the exchange subject_token is a JWT.)

- [ ] **Step 4: Run the generation test**

Run: `cd kdex-fngogen && go test ./cmd/ -run TestGenerate_BearerHandlerFlowsRawToken -v`
Expected: PASS.

- [ ] **Step 5: Regenerate fixtures and run the full suite**

Run: `cd kdex-fngogen && make test`
Expected: PASS. If committed golden fixtures diff, regenerate them per the repo's fixture-update flow and include the regenerated files in the commit.

- [ ] **Step 6: Commit**

```bash
cd kdex-fngogen
git checkout -b feat/fat-token-exchange
git add cmd/templates/main.go.tmpl cmd/main_test.go test-fixtures/
git commit -m "feat: flow raw inbound token to handlers via context

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: fngogen — the `Exchange()` runtime helper library

**Files:**
- Create: `kdex-fngogen/runtime/kdexauth/exchange.go` (a small importable package; confirm the module path with `head -1 kdex-fngogen/go.mod` and use `<module>/runtime/kdexauth`)
- Test: `kdex-fngogen/runtime/kdexauth/exchange_test.go`

> **DEPENDENCY-rule note:** this helper is imported by every generated function, so it is a versioned dependency, not copy-generated code. Put it in a stable package path and keep its surface minimal. If a shared kdex Go module is a better long-term home than the fngogen repo, raise it before implementing — but the fngogen `runtime/` package is the default.

**Interfaces:**
- Consumes: `RequestTokenFromContext` (conceptually — but to avoid importing generated code, the helper takes the raw token explicitly; see signature).
- Produces:
  - `func Exchange(ctx context.Context, cfg Config, resource string) (string, error)`
  - `type Config struct { TokenEndpoint string; SubjectToken string; HTTPClient *http.Client }`
  A generated call site is: `tok, err := kdexauth.Exchange(ctx, kdexauth.Config{TokenEndpoint: os.Getenv("TOKEN_ENDPOINT"), SubjectToken: raw}, target)` where `raw, _ := RequestTokenFromContext(ctx)`.

- [ ] **Step 1: Write the failing test** (`runtime/kdexauth/exchange_test.go`)

```go
func TestExchange_PostsRFC8693FormAndReturnsAccessToken(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"minted.jwt.for.b","token_type":"Bearer","expires_in":300}`))
	}))
	defer srv.Close()

	tok, err := Exchange(context.Background(), Config{
		TokenEndpoint: srv.URL,
		SubjectToken:  "the.inbound.fat",
	}, "/v1/internal")

	require.NoError(t, err)
	assert.Equal(t, "minted.jwt.for.b", tok)
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", gotForm.Get("grant_type"))
	assert.Equal(t, "the.inbound.fat", gotForm.Get("subject_token"))
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", gotForm.Get("subject_token_type"))
	assert.Equal(t, "/v1/internal", gotForm.Get("resource"))
}

func TestExchange_NonJSONOrErrorStatusReturnsError(t *testing.T) {
	// server returns 400 {"error":"invalid_target"} -> Exchange returns a non-nil error mentioning invalid_target
}

func TestExchange_EmptySubjectTokenIsError(t *testing.T) {
	// Config{SubjectToken:""} -> error before any HTTP call
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-fngogen && go test ./runtime/kdexauth/ -run TestExchange -v`
Expected: FAIL — package/func undefined.

- [ ] **Step 3: Implement** (`runtime/kdexauth/exchange.go`)

```go
// Package kdexauth provides the client half of KDex FAT token exchange
// (RFC 8693): a function handler trades its inbound Function Access Token for a
// token addressed to another function's audience, so it can call that function
// directly in-cluster.
package kdexauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Config struct {
	// TokenEndpoint is the host token endpoint, e.g. os.Getenv("ISSUER")+"/-/token".
	TokenEndpoint string
	// SubjectToken is the raw inbound FAT (from RequestTokenFromContext).
	SubjectToken string
	// HTTPClient is optional; http.DefaultClient is used when nil.
	HTTPClient *http.Client
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// Exchange trades cfg.SubjectToken for a JWT addressed to `resource`'s function.
func Exchange(ctx context.Context, cfg Config, resource string) (string, error) {
	if cfg.SubjectToken == "" {
		return "", fmt.Errorf("kdexauth: empty subject token; no authenticated request context")
	}
	if cfg.TokenEndpoint == "" || resource == "" {
		return "", fmt.Errorf("kdexauth: token endpoint and resource are required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {cfg.SubjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {resource},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("kdexauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("kdexauth: token exchange request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("kdexauth: decode token response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		return "", fmt.Errorf("kdexauth: token exchange failed (status %d): %s %s", resp.StatusCode, tr.Error, tr.ErrorDesc)
	}
	return tr.AccessToken, nil
}
```

> **Caching (deferred to a follow-up step, kept out of v1 to stay minimal):** the spec calls for caching by `(sub, resource)`. The exchanged token is short-lived (host `TokenTTL`); add an in-process TTL cache keyed by `sha256(SubjectToken)|resource` only if profiling shows the extra `/-/token` round-trip matters. Track as a follow-up rather than blocking v1.

- [ ] **Step 4: Run tests**

Run: `cd kdex-fngogen && go test ./runtime/kdexauth/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd kdex-fngogen
git add runtime/kdexauth/
git commit -m "feat: kdexauth.Exchange helper (RFC 8693 client)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: host-manager integration test — end-to-end exchange (incl. internal target)

**Files:**
- Test: `kdex-host-manager/internal/host/tokenexchange_integration_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1-3 wired through a real `HostHandler` + `auth.OAuth2` over the httptest mux the other host tests use (mirror `internal/host/mcp_oauth2_e2e_test.go`).

- [ ] **Step 1: Write the integration test**

```go
// TestTokenExchange_EndToEnd_InternalTarget drives the real /-/token mux: mint a
// FAT for function A, POST an RFC 8693 exchange for an INTERNAL function B's
// basePath, and assert the returned JWT is addressed to B's fatAudienceFor and
// carries the subject's re-resolved entitlements.
func TestTokenExchange_EndToEnd_InternalTarget(t *testing.T) {
	// Build a HostHandler with two Ready functions: A (public) and B (spec.Internal),
	// each with a Status.URL; wire auth with a P-256 key and an identity provider
	// that grants "alice" ["functions:/v1/internal:read"].
	// 1. mint a FAT (aud=A.Status.URL, sub=alice) with the host signer
	// 2. POST /-/token grant_type=token-exchange, subject_token=<FAT>, resource="/v1/internal"
	// 3. assert 200, decode access_token, aud == B.Status.URL, iss == host issuer,
	//    entitlements contains "functions:/v1/internal:read"
	// 4. negative: resource="/v1/nope" -> 400 invalid_target
}
```

- [ ] **Step 2: Run it (expect FAIL if any wiring is missing), then make it pass against the real mux**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestTokenExchange_EndToEnd -v`
Expected: PASS once Tasks 1-3 are wired; a failure here means the snapshot wiring (Task 1 Step 5) or the handler branch (Task 3) is not reached.

- [ ] **Step 3: Full module test + lint**

Run: `cd kdex-host-manager && make test && make lint`
Expected: PASS. (Run `make lint` from the workspace root too, per CLAUDE.md.)

- [ ] **Step 4: Commit**

```bash
cd kdex-host-manager
git add internal/host/tokenexchange_integration_test.go
git commit -m "test(host): end-to-end token exchange incl. internal target

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Component 1 (token-exchange grant) → Tasks 2 (mint) + 3 (endpoint/discovery). ✓
- Component 2 (internal-inclusive target resolution) → Task 1 + integration Task 6. ✓
- Component 3 (fngogen raw token in context) → Task 4. ✓
- Component 4 (`Exchange()` helper) → Task 5. ✓
- Component 5 (env config, no CRD change) → Global Constraints + Task 5 call-site note; no CRD task exists (correct). ✓
- Security model (re-resolve entitlements; B enforces) → Task 2 (re-resolve) + asserted in Tasks 2/6. ✓
- Testing (invalid_target, internal target, forged/expired/no-sub, drift guard) → Tasks 2, 3, 6. ✓
- Sub-decisions: re-resolve entitlements (Task 2), `Exchange()` in a runtime lib (Task 5), `act` claim (Task 2, incl. allowlist change). ✓

**Placeholder scan:** No TBD/TODO in required behavior. Two explicitly-deferred, non-blocking items are labeled as follow-ups (Exchange() caching; shared-module home for kdexauth) with a clear default chosen — not placeholders in the v1 deliverable.

**Type consistency:** `ExchangeTargets map[string]string` defined (Task 1) and consumed (Task 3); `ExchangeSubjectToken(subjectToken, targetAudience string) (TokenSet, error)` defined (Task 2) and called (Task 3); `RequestTokenContextKey`/`RequestTokenFromContext` defined (Task 4) and referenced (Task 5 call-site note); `GRANT_TYPE_TOKEN_EXCHANGE` / `errCodeInvalidTarget` introduced in Task 3. Consistent.

## Notes for the executor

- A few existing symbol names must be confirmed by a quick `rg` before editing (called out inline): the `OAuth2` struct's `*Exchanger` field name (`o.AuthExchanger` assumed), the `ResourceAudiences:` wiring site, and whether `TokenResponse` already has an `IssuedTokenType` field. These are grep-and-confirm, not design decisions.
- No `kdex-crds` change anywhere — if a task seems to need one, re-read the spec; the target env is runtime, not a CRD field.
