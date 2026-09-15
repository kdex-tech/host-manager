# client_credentials resource-indicator — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a confidential `client_credentials` client obtain a peer-function-audience token directly by passing an RFC 8707 `resource` indicator, gated by a per-client allowlist — so eum can provision into blobsqlite without the RFC 8693 exchange that #212 now blocks.

**Architecture:** host-manager's token endpoint, on `client_credentials` with a `resource`, mints a FAT-shaped token addressed to `ExchangeTargets[resource]` carrying the client's re-resolved entitlements (reusing `LoginClient`'s resolution — "one context, two audiences"), gated by the client's `allowed-resources` allowlist. eum drops its exchange step and adds `resource=` to its mint. No CRD, no nexus.

**Tech Stack:** Go 1.26.0 (host-manager), Go (enterprise-user-manager), testify/gomega.

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-09-15-client-credentials-resource-indicator-design.md`

## Global Constraints

- No `kdex.dev/v1alpha1` (CRD) change; nexus-manager is NOT a released actor.
- `client_credentials` with **no** `resource` must be byte-for-byte unchanged (host-aud token).
- The resource-aud token carries the SAME `sub`/`azp`/roles/entitlements as the client's host-aud token — differ only in `aud`.
- The #212 `ExchangeSubjectToken` gate is untouched.
- A present-but-unhonorable `resource` fails loud with `invalid_target` — never a silent host-aud downgrade.
- host-manager code on branch `cc-resource-indicator`; commit inside each sub-repo.

## File Structure

- `kdex-host-manager/internal/auth/config.go` — `AuthClient` gains `AllowedResources []string`.
- `kdex-host-manager/internal/auth/loaders.go` — parse `allowed-resources` Secret key.
- `kdex-host-manager/internal/auth/exchange.go` — factor `LoginClient`; add `LoginClientResource`.
- `kdex-host-manager/internal/auth/oauth2.go` — `client_credentials` branch honors `resource`.
- `enterprise-user-manager/functions/eum/store/client.go` — `token()` carries `resource`; drop the exchange.

---

### Task 1: `AllowedResources` on AuthClient + loader

**Files:**
- Modify: `internal/auth/config.go` (`AuthClient`, ~L41-51)
- Modify: `internal/auth/loaders.go` (~L68-116)
- Test: `internal/auth/loaders_test.go`

**Interfaces:**
- Produces: `AuthClient.AllowedResources []string`; loader reads `allowed_resources`/`allowed-resources`.

- [ ] **Step 1: Write the failing test** — append to `loaders_test.go` (mirror the existing `authClientSecret` helper + a loader-invoking test in that file):

```go
func TestAuthClientLoaderParsesAllowedResources(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id":           "eum-blobsqlite",
		"client_secret":       "s3cret",
		"allowed-grant-types": "client_credentials",
		"allowed-resources":   "/db/v1,https://host.example/db/v1",
	})}
	clients, err := AuthClientLoader(secrets) // use this file's actual loader entrypoint/signature
	require.NoError(t, err)
	c, ok := clients["eum-blobsqlite"]
	require.True(t, ok)
	assert.Equal(t, []string{"/db/v1", "https://host.example/db/v1"}, c.AllowedResources)

	// Absent -> empty (not nil-panic).
	secrets2 := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id": "x", "client_secret": "y", "allowed-grant-types": "client_credentials",
	})}
	clients2, err := AuthClientLoader(secrets2)
	require.NoError(t, err)
	assert.Empty(t, clients2["x"].AllowedResources)
}
```

Note: match the loader function's real name/signature as used by the other tests in `loaders_test.go` (they already call it); do not invent `AuthClientLoader` if the file names it differently.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestAuthClientLoaderParsesAllowedResources -v`
Expected: FAIL (compile error — `AllowedResources` undefined).

- [ ] **Step 3: Add the field** — in `config.go` `AuthClient`, after `AllowedScopes`:

```go
	AllowedResources  []string
```

- [ ] **Step 4: Parse it in the loader** — in `loaders.go`, alongside the `allowedScopes` block (~L68-75):

```go
		allowedResourcesStr := string(secret.Data["allowed_resources"])
		if allowedResourcesStr == "" {
			allowedResourcesStr = string(secret.Data["allowed-resources"])
		}
		allowedResources := []string{}
		if allowedResourcesStr != "" {
			allowedResources = strings.Split(allowedResourcesStr, ",")
		}
```

and add to the `AuthClient{...}` literal (~L104):

```go
			AllowedResources:  allowedResources,
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestAuthClientLoaderParsesAllowedResources -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd kdex-host-manager && git add internal/auth/config.go internal/auth/loaders.go internal/auth/loaders_test.go
git commit -m "feat: parse allowed-resources on auth-client Secrets

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Factor `LoginClient`, add `LoginClientResource`

**Files:**
- Modify: `internal/auth/exchange.go` (`LoginClient`, ~L893-983)
- Test: `internal/auth/exchange_client_credentials_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `func (e *Exchanger) LoginClientResource(ctx context.Context, clientID, clientSecret, scope, targetAudience string) (TokenSet, error)` — same authority as `LoginClient`, signed with `targetAudience`. Internal helper `buildClientSigningContext(clientID, clientSecret, scope string) (jwt.MapClaims, string, error)` returns the ready signing-context + granted-scope string.

- [ ] **Step 1: Write the failing test** — append to `exchange_client_credentials_test.go` (reuse that file's Exchanger + client fixture; the existing tests there set up a client with `AllowedGrantTypes: []string{"client_credentials"}`):

```go
func TestLoginClientResource_MintsTargetAudienceWithSameAuthority(t *testing.T) {
	g := NewWithT(t)
	e := newClientCredentialsExchanger(t) // reuse this file's existing setup helper/pattern
	const target = "https://host.example/db/v1" // any non-host audience string

	host, err := e.LoginClient(context.Background(), "eum-blobsqlite", "s3cret", "")
	g.Expect(err).ToNot(HaveOccurred())
	res, err := e.LoginClientResource(context.Background(), "eum-blobsqlite", "s3cret", "", target)
	g.Expect(err).ToNot(HaveOccurred())

	// Same subject + authority, different audience.
	g.Expect(claimString(t, res.AccessToken, "sub")).To(Equal("eum-blobsqlite"))
	g.Expect(audOf(t, res.AccessToken)).To(ConsistOf(target))
	g.Expect(audOf(t, host.AccessToken)).ToNot(ConsistOf(target)) // host token is host-aud
	g.Expect(claimJSON(t, res.AccessToken, "entitlements")).To(Equal(claimJSON(t, host.AccessToken, "entitlements")))
	g.Expect(claimJSON(t, res.AccessToken, "roles")).To(Equal(claimJSON(t, host.AccessToken, "roles")))

	// Bad secret still rejected on the resource path.
	_, err = e.LoginClientResource(context.Background(), "eum-blobsqlite", "wrong", "", target)
	g.Expect(err).To(HaveOccurred())
}
```

Use the token-decoding helpers the existing auth tests use (`claimString`/`audOf`/`claimJSON` are illustrative — reuse whatever `exchange_client_credentials_test.go` / the auth test suite already provides to read a signed token's claims; build a small local one only if none exists).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestLoginClientResource -v`
Expected: FAIL (compile error — `LoginClientResource` undefined).

- [ ] **Step 3: Extract the shared context builder** — refactor `LoginClient` (`exchange.go` ~L893-983). Move everything from the `GetClient`/secret check through the roles/entitlements resolution into a helper, leaving `LoginClient` to build + sign host-aud:

```go
// buildClientSigningContext authenticates the client and builds the signing
// context (sub/azp/scope/roles/entitlements) shared by the host-audience
// client_credentials mint and the resource-audience mint. It does NOT sign.
func (e *Exchanger) buildClientSigningContext(clientID, clientSecret, scope string) (jwt.MapClaims, string, error) {
	if e == nil {
		return nil, "", fmt.Errorf("%w: auth not configured", ErrServerError)
	}
	if !e.config.IsM2MEnabled() {
		return nil, "", fmt.Errorf("%w: M2M auth not configured", ErrServerError)
	}
	client, ok := e.GetClient(clientID)
	if !ok {
		return nil, "", fmt.Errorf("invalid client_id")
	}
	if client.ClientSecret != clientSecret {
		return nil, "", fmt.Errorf("invalid client_secret")
	}
	signingContext := jwt.MapClaims{
		"sub":         clientID,
		"azp":         clientID,
		"auth_method": string(AuthMethodOAuth2),
		"grant_type":  "client_credentials",
	}
	grantedScopes := []string{}
	for _, s := range strings.Split(scope, " ") {
		if s == "" {
			continue
		}
		if len(client.AllowedScopes) > 0 && !slices.Contains(client.AllowedScopes, s) {
			return nil, "", fmt.Errorf("scope %s not allowed for this client", s)
		}
		grantedScopes = append(grantedScopes, s)
	}
	grantedScopeStr := strings.Join(grantedScopes, " ")
	if grantedScopeStr != "" {
		signingContext["scope"] = grantedScopeStr
	}
	wantRoles := len(grantedScopes) == 0 || slices.Contains(grantedScopes, "roles")
	wantEntitlements := len(grantedScopes) == 0 || slices.Contains(grantedScopes, "entitlements")
	if wantRoles || wantEntitlements {
		roles, entitlements, rerr := e.ResolveInternalRolesAndEntitlements(clientID)
		if rerr != nil {
			return nil, "", fmt.Errorf("%w: failed to resolve roles/entitlements for client %s: %v", ErrServerError, clientID, rerr)
		}
		if wantRoles {
			signingContext["roles"] = roles
		}
		if wantEntitlements {
			signingContext["entitlements"] = entitlements
		}
	}
	return signingContext, grantedScopeStr, nil
}
```

Then `LoginClient` becomes:

```go
func (e *Exchanger) LoginClient(ctx context.Context, clientID, clientSecret, scope string) (TokenSet, error) {
	signingContext, grantedScopeStr, err := e.buildClientSigningContext(clientID, clientSecret, scope)
	if err != nil {
		return TokenSet{}, err
	}
	accessToken, err := e.config.Signer.Sign(signingContext)
	if err != nil {
		return TokenSet{Subject: clientID}, fmt.Errorf("%w: failed to sign access token: %v", ErrServerError, err)
	}
	return TokenSet{AccessToken: accessToken, Scope: grantedScopeStr, Subject: clientID}, nil
}
```

Preserve behavior exactly: the `TokenSet{Subject: clientID}` on a sign failure, and the plain (unmarked) errors on `invalid client_id`/`invalid client_secret` (do NOT attach Subject to those — see the #158 comment in the original). Keep the original's doc comments.

- [ ] **Step 4: Add `LoginClientResource`** — new method:

```go
// LoginClientResource is LoginClient signed for a peer resource's audience
// instead of the host: the SAME authenticated client identity + re-resolved
// authority (buildClientSigningContext), addressed to targetAudience so a
// confidential client can call a peer function without an RFC 8693 exchange.
// The caller (token handler) has already verified the resource is permitted for
// this client and resolved targetAudience from ExchangeTargets. No `act` — the
// client is itself the subject.
func (e *Exchanger) LoginClientResource(ctx context.Context, clientID, clientSecret, scope, targetAudience string) (TokenSet, error) {
	signingContext, grantedScopeStr, err := e.buildClientSigningContext(clientID, clientSecret, scope)
	if err != nil {
		return TokenSet{}, err
	}
	signer, err := sign.NewSigner(
		targetAudience,
		e.config.TokenTTL,
		e.config.Issuer,
		&e.config.ActivePair.Private,
		e.config.ActivePair.KeyId,
		e.config.ClaimMapper,
	)
	if err != nil {
		return TokenSet{Subject: clientID}, fmt.Errorf("%w: failed to build signer for %s: %v", ErrServerError, targetAudience, err)
	}
	accessToken, err := signer.Sign(signingContext)
	if err != nil {
		return TokenSet{Subject: clientID}, fmt.Errorf("%w: failed to sign resource token: %v", ErrServerError, err)
	}
	return TokenSet{AccessToken: accessToken, Scope: grantedScopeStr, Subject: clientID}, nil
}
```

- [ ] **Step 5: Run test to verify it passes + no regression**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run 'TestLoginClient' -v && go test ./internal/auth/ -count=1`
Expected: PASS (new test green; existing client_credentials tests unchanged).

- [ ] **Step 6: Commit**

```bash
cd kdex-host-manager && git add internal/auth/exchange.go internal/auth/exchange_client_credentials_test.go
git commit -m "feat: add LoginClientResource (client_credentials, resource-audience)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Token endpoint honors `resource` on `client_credentials`

**Files:**
- Modify: `internal/auth/oauth2.go` (`client_credentials` case, ~L430-436)
- Test: `internal/auth/oauth2_client_credentials_resource_test.go` (new) or the existing token-handler test file

**Interfaces:**
- Consumes: `client.AllowedResources` (Task 1), `LoginClientResource` (Task 2), `o.ExchangeTargets`, `errCodeInvalidTarget` (exists, `oautherr.go:74`).

- [ ] **Step 1: Write the failing test** — drive the real token handler (model on the existing token-handler tests, e.g. `oauth2_tokenexchange_test.go` / `oauth2_test.go`, which POST form bodies to the handler with a configured `OAuth2{ExchangeTargets:…, AuthExchanger:…}` and a client). Assert:

```go
// client_credentials + allowed+registered resource -> 200, token aud=target.
// (allowed-resources on the client includes "/db/v1"; ExchangeTargets["/db/v1"]="aud-db")
func TestTokenHandler_ClientCredentialsResource_MintsTargetAud(t *testing.T) { /* … */ }
// resource NOT in the client's allowed-resources -> 400 invalid_target.
func TestTokenHandler_ClientCredentialsResource_NotAllowed_InvalidTarget(t *testing.T) { /* … */ }
// resource in allowlist but NOT a registered ExchangeTarget -> 400 invalid_target.
func TestTokenHandler_ClientCredentialsResource_UnknownTarget_InvalidTarget(t *testing.T) { /* … */ }
// client_credentials with NO resource -> host-aud token (regression, unchanged).
func TestTokenHandler_ClientCredentials_NoResource_HostAud(t *testing.T) { /* … */ }
```

Each asserts the HTTP status and, for the success case, decodes the returned `access_token` and checks its `aud`. Reuse the existing token-handler test scaffolding in the auth package for wiring the `OAuth2` handler, a confidential client (`Public:false`, `AllowedGrantTypes:["client_credentials"]`, `AllowedResources:["/db/v1"]`), and an `ExchangeTargets` map; do not build a new harness if one exists.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestTokenHandler_ClientCredentials -v`
Expected: FAIL — resource currently ignored; success case returns a host-aud token, `invalid_target` cases return 200/host-aud.

- [ ] **Step 3: Wire the branch** — in `oauth2.go`, replace the `client_credentials` case (~L430-436):

```go
	case "client_credentials":
		if client.Public {
			err = fmt.Errorf("client_credentials grant_type is not supported for public clients")
			writeOAuthError(w, http.StatusBadRequest, errCodeUnauthorizedClient, "client_credentials is not supported for public clients")
			return
		}
		if resource != "" {
			targetAudience, isTarget := o.ExchangeTargets[resource]
			if !isTarget || !slices.Contains(client.AllowedResources, resource) {
				err = fmt.Errorf("resource %q not permitted for client %q", resource, clientId)
				writeOAuthError(w, http.StatusBadRequest, errCodeInvalidTarget, "requested resource is not permitted for this client")
				return
			}
			ts, err = o.AuthExchanger.LoginClientResource(r.Context(), clientId, clientSecret, scope, targetAudience)
		} else {
			ts, err = o.AuthExchanger.LoginClient(r.Context(), clientId, clientSecret, scope)
		}
```

Notes for the implementer:
- Confirm the OAuth2 struct field is `o.ExchangeTargets` (`map[string]string`) and the interface `o.AuthExchanger` can expose `LoginClientResource` — add it to that interface if `AuthExchanger` is an interface type (mirror how `LoginClient` is declared on it).
- The existing empty-subject guard (~L476) and `writeResourcePATResponse` fall-through (~L488, returns false for `client_credentials`) are unchanged — the resource-aud `ts` flows through to the standard `TokenResponse`.

- [ ] **Step 4: Run test to verify it passes + full package**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run TestTokenHandler_ClientCredentials -v && go test ./internal/auth/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd kdex-host-manager && git add internal/auth/oauth2.go internal/auth/oauth2_client_credentials_resource_test.go
git commit -m "feat: honor RFC 8707 resource on client_credentials (allowlisted)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: eum store client mints with `resource`, drops the exchange

**Files:**
- Modify: `enterprise-user-manager/functions/eum/store/client.go`
- Test: `enterprise-user-manager/functions/eum/store/client_test.go`

**Interfaces:**
- Consumes: host-manager's new `resource` behavior (Task 3) — but the eum change is independently testable against a stub token endpoint.

- [ ] **Step 1: Write the failing test** — in `client_test.go` (reuse its existing httptest stub pattern for the token endpoint):

```go
// token() posts resource=<cfg.Resource> so the mint returns a blobsqlite-aud
// token directly; no RFC 8693 exchange call is made.
func TestClientToken_PostsResourceAndSkipsExchange(t *testing.T) {
	var gotForm url.Values
	var exchangeCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange" {
			exchangeCalled = true
		}
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"BLOBTOKEN","expires_in":3600}`))
	}))
	defer srv.Close()

	c := New(Config{TokenURL: srv.URL, ClientID: "eum-blobsqlite", ClientSecret: "s", Resource: "/db/v1", HTTPTimeout: 5 * time.Second})
	tok, err := c.token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "BLOBTOKEN", tok)
	require.Equal(t, "/db/v1", gotForm.Get("resource"))
	require.Equal(t, "client_credentials", gotForm.Get("grant_type"))
	require.False(t, exchangeCalled, "must not perform an RFC 8693 exchange")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rotty/projects/RSI/sub-projects/enterprise-user-manager && go test ./functions/eum/store/ -run TestClientToken_PostsResourceAndSkipsExchange -v`
Expected: FAIL — `token()` posts no `resource`; the consumers still call `exchangedToken` (exchange fires).

- [ ] **Step 3: Add `resource` to `token()`** — in `client.go` `token()` (~L97), build the form with the resource when configured:

```go
	form := "grant_type=client_credentials"
	if c.cfg.Resource != "" {
		form += "&resource=" + url.QueryEscape(c.cfg.Resource)
	}
```

(add `net/url` to imports if not present).

- [ ] **Step 4: Point consumers at `token()` and remove the exchange** — replace every call to `c.exchangedToken(ctx)` with `c.token(ctx)` (grep the package: `rg -n exchangedToken functions/eum/store`), then delete `exchangedToken`, the `cachedExchToken`/`exchExp` struct fields, `exchangedTokenExpiry`, and the now-unused `kdexauth` import. Confirm nothing else needs a host-aud token from `token()` (it is now blobsqlite-audienced).

- [ ] **Step 5: Run test + package**

Run: `cd /home/rotty/projects/RSI/sub-projects/enterprise-user-manager && go test ./functions/eum/store/ -count=1`
Expected: PASS (new test green; existing store tests updated for the dropped exchange where they asserted it).

- [ ] **Step 6: Commit**

```bash
cd /home/rotty/projects/RSI/sub-projects/enterprise-user-manager
git add functions/eum/store/client.go functions/eum/store/client_test.go
git commit -m "feat: mint blobsqlite-audience token via client_credentials resource indicator

Drops the RFC 8693 exchange (blocked by host-manager #212 for host-aud
subject_tokens); the client_credentials mint now carries resource= and
returns a blobsqlite-audienced token directly.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Verify + release

**Files:** verify only; release host-manager + eum.

- [ ] **Step 1: host-manager full verify**

Run: `cd kdex-host-manager && make test && make lint && go test -race ./internal/auth/...`
Expected: PASS (regression: no-resource client_credentials unchanged; #212 exchange tests intact).

- [ ] **Step 2: eum verify**

Run: `cd /home/rotty/projects/RSI/sub-projects/enterprise-user-manager && go test ./... && (make lint 2>/dev/null || golangci-lint run ./... 2>/dev/null || echo "no lint target")`
Expected: PASS.

- [ ] **Step 3: Merge + release host-manager** — after review, `--ff-only` merge `cc-resource-indicator` → `main` (no merge commit), push, tag **v0.16.0** (new grant capability), push tag (triggers CI image+chart). Release eum (its own tag/registry per that repo's flow).

- [ ] **Step 4: Ops (record for the deploy, do not perform here)** — the `eum-blobsqlite` auth-client Secret needs `allowed-resources: <blobsqlite resource>` (the same value eum sends as `BLOBSQLITE_RESOURCE`). Deploy order on the public tenant: host-manager v0.16.0 first, then the Secret key, then eum — the exchange stays broken until eum is repinned, so it does not self-heal until eum ships.

---

## Notes for the executor

- Line numbers are approximate (`~L…`) — locate by symbol.
- Do NOT modify `ExchangeSubjectToken` or its #212 gate.
- If `AuthExchanger` is an interface, `LoginClientResource` must be added to it (mirror `LoginClient`), and any mock in the token-handler tests updated.
- Reuse existing test helpers (token decoding, handler wiring, httptest stubs) rather than building new harnesses; only add a helper if none exists.
