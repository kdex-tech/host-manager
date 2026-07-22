# Capability-URL Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `mint_token` mint a capability as a single-use, credential-less `https://<host>/-/transfer/<handle>` download URL, in addition to the existing bearer token.

**Architecture:** `mint_token` gains `delivery:"url"` + a concrete `target:{method,path}`. On URL delivery host-manager stores a claims-only record in the existing `cap` cache under `transfer:<handle>` (self-expiring at the token TTL) and returns the link. `GET /-/transfer/<handle>` looks the record up, decrements the existing `kdx_cap` budget, injects an `AuthContext` from the stored claims, and re-dispatches the bound target through `hh.Mux` — so the proxy identity gate, per-op `security` check, FAT re-mint, and knowdb enforcement all run unchanged. The URL carries no credential.

**Tech Stack:** Go 1.26.0, `net/http.ServeMux` (Go 1.22 routing), `github.com/golang-jwt/jwt/v5`, the in-repo `internal/cache` (Valkey + in-memory), `github.com/onsi/gomega` for tests, kubebuilder CRDs (`kdex.dev/crds`).

## Global Constraints

- **Go version pinned to 1.26.0** across kdex-crds / kdex-host-manager — do not change `go.mod` toolchain lines.
- **Reuse the existing `mint_token` clamps verbatim** — `MintTokenTTLCap` (default 60s), `MintTokenUsesCap` (default 32), destructive-verb forcing. Add **no** new TTL/uses config.
- **URL delivery forces `uses = 1`** in code (config-free), and is **download-only** — `target.method` must be `GET`.
- **Reject `target.path` under the reserved `/-/` prefix** — a redemption re-dispatch into a system route (including `/-/transfer/...`) must be impossible.
- **Claims-only handle** — never store or embed the signed JWT in the URL; store `{jti, sub, entitlements, target}` only.
- **Uniform `410 Gone`** for every non-redeemable case (unknown / spent / expired / wrong-method handle) with body `This transfer link is no longer valid.` — this is the one deliberate divergence from the proxy's anti-enum `404`.
- **CRD field additions propagate via `./updateCrdUsage.sh -t`** from the workspace root (releases both host-manager and nexus-manager); observe the two-commit plan-time-validation rule.
- **Entitlement semantics** are owned by `github.com/kdex-tech/entitlements/go`; do not reimplement matching. `mint_token` attenuation (`VerifyAttenuation`) is unchanged.

## File Structure

**kdex-crds (`../kdex-crds`):**
- Modify `api/v1alpha1/types.go` — add `URLDelivery bool` to the `MintToken` struct.
- Regenerated (via `make manifests generate docs`): `config/crd/bases/*.yaml`, `api/v1alpha1/zz_generated.deepcopy.go` (bool → no deepcopy change), `CRD_REFERENCE.md`.

**kdex-host-manager:**
- Modify `internal/auth/config.go` — add `MintTokenURLDelivery bool` to `Config`; set it in `applyMintTokenPolicy`.
- Modify `internal/host/mint_token.go` — add `Delivery`/`Target` to `MintTokenRequest`, `URL` to `MintTokenResult`, the `TransferTarget` type, `validateTransferTarget`, the URL-delivery branch in `mintCapabilityToken`, and `delivery`/`target` in `mintTokenDescriptor`'s input schema; thread `baseURL` into `mintCapabilityToken` and `*http.Request` into `writeMintTokenRPC`.
- Create `internal/host/transfer.go` — `transferRecord`, cache helpers (`capCache`, `storeTransferRecord`, `loadTransferRecord`), `newTransferHandle`, `transferBaseURL`, `transferPath`, `transferHandler`, `TransferGet`.
- Modify `internal/host/host.go` — call `hh.transferHandler(mux, registeredPaths)` in the system-handler registration block (alongside `hh.apitokensHandler(...)`).
- Modify `internal/host/proxy.go` — update the `writeMintTokenRPC` call site to pass `r`.
- Tests: extend `internal/host/mint_token_test.go`; new `internal/host/transfer_test.go`; extend `internal/auth/config_test.go`.

---

## Task 1: CRD `urlDelivery` field + propagation

**Files:**
- Modify: `../kdex-crds/api/v1alpha1/types.go` (the `MintToken` struct, ~line 275)
- Regenerate: `../kdex-crds/config/crd/bases/*.yaml`, `../kdex-crds/CRD_REFERENCE.md`

**Interfaces:**
- Produces: `kdexv1alpha1.MintToken.URLDelivery bool` (json `urlDelivery`) — consumed by Task 2.

- [ ] **Step 1: Add the field to the `MintToken` struct**

In `../kdex-crds/api/v1alpha1/types.go`, add as the last field of `type MintToken struct` (after `DestructiveVerbs`):

```go
	// urlDelivery permits minting a capability as a redeemable
	// /-/transfer/<handle> URL (delivery:"url") in addition to the default
	// bearer token. Off unless set: handing out a credential-less link is a
	// distinct risk from minting a bearer token, so a host opts in explicitly.
	// +kubebuilder:validation:Optional
	URLDelivery bool `json:"urlDelivery,omitempty" protobuf:"varint,5,opt,name=urlDelivery"`
```

- [ ] **Step 2: Regenerate manifests + docs**

Run:
```bash
cd ../kdex-crds && make manifests generate docs
```
Expected: no errors; working tree now shows changes under `config/crd/bases/` and `CRD_REFERENCE.md`.

- [ ] **Step 3: Verify the field generated**

Run:
```bash
cd ../kdex-crds && rg -n 'urlDelivery' config/crd/bases/*.yaml CRD_REFERENCE.md
```
Expected: `urlDelivery` appears as a `boolean` property under the host's `mintToken` object in the CRD YAML and in the reference doc.

- [ ] **Step 4: Commit in kdex-crds**

```bash
cd ../kdex-crds && git add -A && git commit -m "feat(minttoken): add urlDelivery opt-in field (host-manager#151)"
```

- [ ] **Step 5: Propagate the CRD to host-manager + nexus-manager**

From the workspace root, bump the crds tag and update dependents' `go.mod`/`go.sum`:
```bash
cd .. && ./updateCrdUsage.sh -t
```
Expected: kdex-crds patch tag incremented + pushed; `kdex-host-manager/go.mod` and `kdex-nexus-manager/go.mod` now reference the new tag. (This pushes a tag/commits — surface the output at the review checkpoint. Use `./updateCrdUsage.sh -t -n` to leave the dependent go.mod/go.sum edits uncommitted for manual review if preferred.)

- [ ] **Step 6: Verify host-manager sees the new field**

```bash
cd kdex-host-manager && go build ./... && rg -n 'URLDelivery' $(go env GOMODCACHE)/kdex.dev/crds@*/api/v1alpha1/types.go | head -1
```
Expected: build succeeds; `URLDelivery` present in the resolved module.

---

## Task 2: Config policy wiring (`MintTokenURLDelivery`)

**Files:**
- Modify: `internal/auth/config.go` (the `Config` struct ~line 66; `applyMintTokenPolicy` ~line 345)
- Test: `internal/auth/config_test.go`

**Interfaces:**
- Consumes: `kdexv1alpha1.MintToken.URLDelivery` (Task 1).
- Produces: `auth.Config.MintTokenURLDelivery bool` — consumed by Tasks 5, 6, 7.

- [ ] **Step 1: Write the failing test**

Append to `internal/auth/config_test.go`:

```go
func TestApplyMintTokenPolicy_URLDelivery(t *testing.T) {
	g := NewWithT(t)

	on := &Config{}
	applyMintTokenPolicy(on, &kdexv1alpha1.MintToken{Enabled: true, URLDelivery: true})
	g.Expect(on.MintTokenEnabled).To(BeTrue())
	g.Expect(on.MintTokenURLDelivery).To(BeTrue())

	off := &Config{}
	applyMintTokenPolicy(off, &kdexv1alpha1.MintToken{Enabled: true})
	g.Expect(off.MintTokenURLDelivery).To(BeFalse())
}
```

If `config_test.go` lacks the imports, ensure it imports `. "github.com/onsi/gomega"` and `kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"` (mirror `internal/host/mint_token_test.go`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestApplyMintTokenPolicy_URLDelivery -v`
Expected: FAIL — `on.MintTokenURLDelivery undefined (type *Config has no field ...)`.

- [ ] **Step 3: Add the field + wire it**

In `internal/auth/config.go`, add to the `Config` struct immediately after `MintTokenDestructiveVerbs []string`:

```go
	MintTokenURLDelivery      bool
```

In `applyMintTokenPolicy`, add before its closing brace (after the `DestructiveVerbs` block):

```go
	cfg.MintTokenURLDelivery = mintToken.URLDelivery
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/auth/ -run TestApplyMintTokenPolicy_URLDelivery -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/config.go internal/auth/config_test.go
git commit -m "feat(minttoken): resolve spec.auth.mintToken.urlDelivery into Config (#151)"
```

---

## Task 3: Mint request/result/target types + target validation

**Files:**
- Modify: `internal/host/mint_token.go` (structs ~lines 51-64)
- Test: `internal/host/mint_token_test.go`

**Interfaces:**
- Produces:
  - `type TransferTarget struct { Method string; Path string }`
  - `MintTokenRequest.Delivery string` (json `delivery`), `MintTokenRequest.Target *TransferTarget` (json `target`)
  - `MintTokenResult.URL string` (json `url`), `MintTokenResult.Token` now `json:"token,omitempty"`
  - `func validateTransferTarget(t *TransferTarget) error`
  - const `deliveryURL = "url"`
  - Consumed by Tasks 5, 6.

- [ ] **Step 1: Write the failing test**

Append to `internal/host/mint_token_test.go`:

```go
func TestValidateTransferTarget(t *testing.T) {
	g := NewWithT(t)

	g.Expect(validateTransferTarget(nil)).To(HaveOccurred())
	g.Expect(validateTransferTarget(&TransferTarget{Method: "POST", Path: "/api/v1/files/x/content"})).To(HaveOccurred())
	g.Expect(validateTransferTarget(&TransferTarget{Method: "GET", Path: "api/v1/files/x"})).To(HaveOccurred())        // relative
	g.Expect(validateTransferTarget(&TransferTarget{Method: "GET", Path: "/-/transfer/abc"})).To(HaveOccurred())       // reserved
	g.Expect(validateTransferTarget(&TransferTarget{Method: "get", Path: "/api/v1/files/x/content"})).ToNot(HaveOccurred())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run TestValidateTransferTarget -v`
Expected: FAIL — `undefined: validateTransferTarget` / `undefined: TransferTarget`.

- [ ] **Step 3: Add the types + validator**

In `internal/host/mint_token.go`, add the delivery constant near the top (after the imports/`ctxKey` block):

```go
// deliveryURL is the MintTokenRequest.Delivery value selecting redeemable-URL
// delivery. Any other value (including "" / "bearer") selects the default
// bearer-token delivery.
const deliveryURL = "url"

// TransferTarget is the single concrete operation a delivery:"url" capability
// authorizes. Download-only in this release: Method must be GET.
type TransferTarget struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// validateTransferTarget enforces the download-only, non-reserved, absolute-path
// contract for a URL-delivery target.
func validateTransferTarget(t *TransferTarget) error {
	if t == nil {
		return fmt.Errorf(`delivery "url" requires a target`)
	}
	if !strings.EqualFold(strings.TrimSpace(t.Method), http.MethodGet) {
		return fmt.Errorf("unsupported target method %q (only GET is supported)", t.Method)
	}
	if !strings.HasPrefix(t.Path, "/") {
		return fmt.Errorf("target path must be an absolute path beginning with /")
	}
	if strings.HasPrefix(t.Path, "/-/") {
		return fmt.Errorf("target path must not be under the reserved /-/ prefix")
	}
	return nil
}
```

Extend `MintTokenRequest` (add the two fields after `Uses int`):

```go
	Delivery string          `json:"delivery,omitempty"`
	Target   *TransferTarget `json:"target,omitempty"`
```

Extend `MintTokenResult` — change `Token`'s tag to `omitempty` and add `URL`:

```go
	Token         string   `json:"token,omitempty"`
	URL           string   `json:"url,omitempty"`
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/host/ -run TestValidateTransferTarget -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/host/mint_token.go internal/host/mint_token_test.go
git commit -m "feat(minttoken): add delivery/target request fields + target validation (#151)"
```

---

## Task 4: Transfer record + cache/handle/URL helpers

**Files:**
- Create: `internal/host/transfer.go`
- Test: `internal/host/transfer_test.go`

**Interfaces:**
- Produces:
  - `type transferRecord struct { JTI string; Sub string; Entitlements []string; Target TransferTarget }`
  - const `transferKeyPrefix = "transfer:"`
  - `func newTransferHandle() (string, error)`
  - `func (hh *HostHandler) capCache() cache.Cache`
  - `func (hh *HostHandler) storeTransferRecord(ctx, handle string, rec transferRecord, ttl time.Duration) error`
  - `func (hh *HostHandler) loadTransferRecord(ctx, handle string) (transferRecord, bool)`
  - `func transferBaseURL(r *http.Request) string`
  - Consumed by Tasks 5, 6.

- [ ] **Step 1: Write the failing test**

Create `internal/host/transfer_test.go`:

```go
package host

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	. "github.com/onsi/gomega"
)

func TestTransferRecordRoundTrip(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{cacheManager: mgr}
	ctx := context.Background()

	rec := transferRecord{
		JTI:          "j1",
		Sub:          "alice",
		Entitlements: []string{"functions:/api/v1/files:read"},
		Target:       TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
	}
	g.Expect(hh.storeTransferRecord(ctx, "h1", rec, time.Minute)).ToNot(HaveOccurred())

	got, ok := hh.loadTransferRecord(ctx, "h1")
	g.Expect(ok).To(BeTrue())
	g.Expect(got).To(Equal(rec))

	_, ok = hh.loadTransferRecord(ctx, "missing")
	g.Expect(ok).To(BeFalse())
}

func TestNewTransferHandleUnique(t *testing.T) {
	g := NewWithT(t)
	a, err := newTransferHandle()
	g.Expect(err).ToNot(HaveOccurred())
	b, _ := newTransferHandle()
	g.Expect(a).ToNot(Equal(b))
	g.Expect(len(a)).To(BeNumerically(">=", 43)) // 32 bytes base64url (no pad)
}

func TestTransferBaseURL(t *testing.T) {
	g := NewWithT(t)
	r := httptest.NewRequest("POST", "https://ignored/api/v1/mcp", nil)
	r.Header.Set("X-Forwarded-Host", "dev.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	g.Expect(transferBaseURL(r)).To(Equal("https://dev.example"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run 'TestTransferRecordRoundTrip|TestNewTransferHandleUnique|TestTransferBaseURL' -v`
Expected: FAIL — undefined `transferRecord` / `storeTransferRecord` / `newTransferHandle` / `transferBaseURL`.

- [ ] **Step 3: Create the helpers**

Create `internal/host/transfer.go`:

```go
package host

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
)

// transferKeyPrefix namespaces URL-delivery records in the shared "cap" cache
// class (the same class holding the "uses:<jti>" budget counters).
const transferKeyPrefix = "transfer:"

// transferRecord is the server-side capability a /-/transfer/<handle> URL maps
// back to. Claims-only: the signed JWT is never stored or embedded in the URL —
// the unguessable handle plus this record IS the credential, and downstream
// enforcement re-checks the entitlements.
type transferRecord struct {
	JTI          string         `json:"jti"`
	Sub          string         `json:"sub"`
	Entitlements []string       `json:"entitlements"`
	Target       TransferTarget `json:"target"`
}

// newTransferHandle returns a 256-bit unguessable, URL-safe handle.
func newTransferHandle() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// capCache returns the host's bounded-capability cache (nil when no cache
// manager is configured — envtest/dev without Valkey).
func (hh *HostHandler) capCache() cache.Cache {
	if hh.cacheManager == nil {
		return nil
	}
	return hh.cacheManager.GetCache("cap", cache.CacheOptions{Uncycled: true})
}

// storeTransferRecord persists rec under transfer:<handle> with the given TTL.
func (hh *HostHandler) storeTransferRecord(ctx context.Context, handle string, rec transferRecord, ttl time.Duration) error {
	c := hh.capCache()
	if c == nil {
		return errNoCache
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return c.Set(ctx, transferKeyPrefix+handle, string(b), cache.WithTTL(ttl))
}

// loadTransferRecord reads and decodes the record for handle. ok=false on a
// missing/expired key, a read error, or a decode error (all fail-closed).
func (hh *HostHandler) loadTransferRecord(ctx context.Context, handle string) (transferRecord, bool) {
	c := hh.capCache()
	if c == nil {
		return transferRecord{}, false
	}
	val, exists, _, err := c.Get(ctx, transferKeyPrefix+handle)
	if err != nil || !exists {
		return transferRecord{}, false
	}
	var rec transferRecord
	if json.Unmarshal([]byte(val), &rec) != nil {
		return transferRecord{}, false
	}
	return rec, true
}

// transferBaseURL is the caller-facing scheme://host prefix for a redemption
// URL, derived from the forwarded request address; "" when unknown.
func transferBaseURL(r *http.Request) string {
	host := fwdHost(r)
	if host == "" {
		return ""
	}
	return fwdScheme(r) + "://" + host
}
```

Add the sentinel error to `transfer.go` (used above and in Task 5):

```go
// errNoCache is returned when URL delivery is requested but no cache manager is
// available to hold the handle record / budget counter.
var errNoCache = fmt.Errorf("mint_token url delivery requires a configured cache")
```

Add `"fmt"` to the import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/host/ -run 'TestTransferRecordRoundTrip|TestNewTransferHandleUnique|TestTransferBaseURL' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/host/transfer.go internal/host/transfer_test.go
git commit -m "feat(minttoken): transfer record + handle/URL cache helpers (#151)"
```

---

## Task 5: Mint URL-delivery branch

**Files:**
- Modify: `internal/host/mint_token.go` (`mintCapabilityToken` ~line 96; `writeMintTokenRPC` ~line 248)
- Modify: `internal/host/proxy.go` (the `writeMintTokenRPC` call, ~line 594)
- Test: `internal/host/mint_token_test.go`

**Interfaces:**
- Consumes: `validateTransferTarget`, `TransferTarget` (Task 3); `newTransferHandle`, `storeTransferRecord`, `transferBaseURL`, `errNoCache` (Task 4); `Config.MintTokenURLDelivery` (Task 2).
- Produces: `mintCapabilityToken(ctx, sub, held, req, baseURL string)` and `writeMintTokenRPC(w, r *http.Request, id, sub, held, args)` — the new signatures every caller must use.

- [ ] **Step 1: Write the failing test**

Append to `internal/host/mint_token_test.go`:

```go
func testURLAuthConfig(t *testing.T) *auth.Config {
	c := testAuthConfigForMint(t)
	c.MintTokenURLDelivery = true
	return c
}

func TestMintCapabilityToken_URLDelivery(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{authConfig: testURLAuthConfig(t), cacheManager: mgr}

	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"functions:/api/v1/files:read"},
		MintTokenRequest{
			Entitlements: []string{"functions:/api/v1/files:read"},
			Delivery:     "url",
			Uses:         5, // must be forced to 1
			Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
		},
		"https://dev.example")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Token).To(BeEmpty())
	g.Expect(res.UsesRemaining).To(Equal(1))
	g.Expect(res.URL).To(HavePrefix("https://dev.example/-/transfer/"))

	// The handle resolves to a stored record with the bound target.
	handle := strings.TrimPrefix(res.URL, "https://dev.example/-/transfer/")
	rec, ok := hh.loadTransferRecord(context.Background(), handle)
	g.Expect(ok).To(BeTrue())
	g.Expect(rec.Sub).To(Equal("alice"))
	g.Expect(rec.Target.Path).To(Equal("/api/v1/files/abc/content"))
	g.Expect(rec.Entitlements).To(Equal([]string{"functions:/api/v1/files:read"}))
}

func TestMintCapabilityToken_URLDelivery_Rejections(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	ent := []string{"functions:/api/v1/files:read"}

	// Feature off.
	off := &HostHandler{authConfig: testAuthConfigForMint(t), cacheManager: mgr}
	_, err := off.mintCapabilityToken(context.Background(), "alice", ent,
		MintTokenRequest{Entitlements: ent, Delivery: "url",
			Target: &TransferTarget{Method: "GET", Path: "/api/v1/files/x"}}, "https://dev.example")
	g.Expect(err).To(HaveOccurred())

	on := &HostHandler{authConfig: testURLAuthConfig(t), cacheManager: mgr}
	// Missing target.
	_, err = on.mintCapabilityToken(context.Background(), "alice", ent,
		MintTokenRequest{Entitlements: ent, Delivery: "url"}, "https://dev.example")
	g.Expect(err).To(HaveOccurred())
	// Reserved /-/ target.
	_, err = on.mintCapabilityToken(context.Background(), "alice", ent,
		MintTokenRequest{Entitlements: ent, Delivery: "url",
			Target: &TransferTarget{Method: "GET", Path: "/-/state/"}}, "https://dev.example")
	g.Expect(err).To(HaveOccurred())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run 'TestMintCapabilityToken_URLDelivery' -v`
Expected: FAIL — too many arguments to `mintCapabilityToken` (signature is still 4-arg).

- [ ] **Step 3: Rework `mintCapabilityToken` for URL delivery**

In `internal/host/mint_token.go`, change the signature:

```go
func (hh *HostHandler) mintCapabilityToken(ctx context.Context, sub string, held []string, req MintTokenRequest, baseURL string) (MintTokenResult, error) {
```

Immediately after the existing `len(req.Entitlements) == 0` guard, add the URL-delivery precondition block:

```go
	isURL := req.Delivery == deliveryURL
	if isURL {
		if !cfg.MintTokenURLDelivery {
			return MintTokenResult{}, fmt.Errorf("url delivery is not enabled on this host")
		}
		if err := validateTransferTarget(req.Target); err != nil {
			return MintTokenResult{}, err
		}
		if hh.capCache() == nil {
			return MintTokenResult{}, errNoCache
		}
	}
```

In the uses-clamping section, after the destructive-verb block, force single-use for URL delivery:

```go
	if isURL {
		uses = 1
	}
```

The signing + counter-provisioning block is unchanged EXCEPT capture the `jti` so the URL branch can key its record. Replace the existing counter block (the `if hh.cacheManager != nil { ... }` around lines 159-170) with one that also remembers the jti:

```go
	// Provision the bounded-use counter keyed by the token's jti; keep the jti
	// for URL delivery's handle record.
	var jti string
	if hh.cacheManager != nil {
		parsed, _, perr := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
		if perr == nil {
			if mc, ok := parsed.Claims.(jwt.MapClaims); ok {
				if j, ok := mc["jti"].(string); ok && j != "" {
					jti = j
					capCache := hh.cacheManager.GetCache("cap", cache.CacheOptions{Uncycled: true})
					_ = capCache.Set(ctx, "uses:"+jti, strconv.Itoa(uses), cache.WithTTL(ttl))
				}
			}
		}
	}
```

Replace the final `return MintTokenResult{...}` with a delivery-aware return:

```go
	result := MintTokenResult{
		ExpiresAt:     time.Now().Add(ttl).Unix(),
		Entitlements:  req.Entitlements,
		UsesRemaining: uses,
	}
	if isURL {
		if jti == "" {
			return MintTokenResult{}, errNoCache
		}
		handle, herr := newTransferHandle()
		if herr != nil {
			return MintTokenResult{}, fmt.Errorf("mint handle: %w", herr)
		}
		if serr := hh.storeTransferRecord(ctx, handle, transferRecord{
			JTI:          jti,
			Sub:          sub,
			Entitlements: req.Entitlements,
			Target:       *req.Target,
		}, ttl); serr != nil {
			return MintTokenResult{}, serr
		}
		result.URL = baseURL + "/-/transfer/" + handle
		return result, nil
	}
	result.Token = token
	return result, nil
```

- [ ] **Step 4: Update `writeMintTokenRPC` + its call site**

Change `writeMintTokenRPC` in `internal/host/mint_token.go` to take the request and thread `baseURL`:

```go
func (hh *HostHandler) writeMintTokenRPC(w http.ResponseWriter, r *http.Request, id json.RawMessage, sub string, held []string, args MintTokenRequest) {
	w.Header().Set("Content-Type", "application/json")
	res, err := hh.mintCapabilityToken(context.Background(), sub, held, args, transferBaseURL(r))
	// ... rest unchanged ...
```

In `internal/host/proxy.go` (~line 594), update the call:

```go
					hh.writeMintTokenRPC(w, r, id, sub, held, args)
```

- [ ] **Step 5: Update the existing direct callers of `mintCapabilityToken` in tests**

The bearer tests call `mintCapabilityToken` with 4 args; add a trailing `""`. Update these call sites in `internal/host/mint_token_test.go`: `TestMintCapabilityToken_AttenuatesAndSignsHostAudience`, `TestMintCapabilityToken_RejectsOverBroad`, `TestMintCapabilityToken_ClampsTTL`, `TestMintCapabilityToken_DestructiveVerbForcing`, `TestMintCapabilityToken_ProvisionsCounter`. Each gets `, "")` appended before the closing paren of the `mintCapabilityToken(...)` call.

Example (first one):
```go
	res, err := hh.mintCapabilityToken(context.Background(), "alice", held, MintTokenRequest{
		Entitlements: []string{"functions:/api/v1/files:write"},
		TTLSeconds:   30,
	}, "")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/host/ -run 'TestMintCapabilityToken' -v`
Expected: PASS — both new URL tests and all five updated bearer tests.

- [ ] **Step 7: Commit**

```bash
git add internal/host/mint_token.go internal/host/proxy.go internal/host/mint_token_test.go
git commit -m "feat(minttoken): mint delivery:url as a /-/transfer handle+URL (#151)"
```

---

## Task 6: Redemption handler + re-dispatch

**Files:**
- Modify: `internal/host/transfer.go` (add `transferPath`, `transferHandler`, `TransferGet`)
- Test: `internal/host/transfer_test.go`

**Interfaces:**
- Consumes: `loadTransferRecord`, `capCache`, `transferRecord` (Task 4); `auth.SetAuthContext` / `auth.AuthContext` (`internal/auth`); `hh.Mux`, `hh.mu` (`internal/host/host.go`); `Config.MintTokenURLDelivery` (Task 2).
- Produces:
  - const `transferPath = "/-/transfer/{handle}"`
  - `func (hh *HostHandler) transferHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo)`
  - `func (hh *HostHandler) TransferGet(w http.ResponseWriter, r *http.Request)`
  - Consumed by Tasks 7, 8.

- [ ] **Step 1: Write the failing test**

Append to `internal/host/transfer_test.go` (add imports `"net/http"`, `"github.com/kdex-tech/host-manager/internal/auth"`):

```go
func TestTransferGet_RedispatchesAndDecrements(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)

	// A stub "function" registered on hh.Mux at the target's subtree. It reports
	// the entitlements the injected AuthContext carried and the path it saw.
	mux := http.NewServeMux()
	var sawPath string
	var sawEnts any
	mux.HandleFunc("GET /api/v1/files/", func(w http.ResponseWriter, r *http.Request) {
		ac, _ := auth.GetAuthContext(r.Context())
		sawPath = r.URL.Path
		sawEnts = ac["entitlements"]
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("FILEBYTES"))
	})

	hh := &HostHandler{cacheManager: mgr, Mux: mux}
	ctx := context.Background()
	c := mgr.GetCache("cap", cache.CacheOptions{Uncycled: true})
	_ = c.Set(ctx, "uses:j1", "1")
	_ = hh.storeTransferRecord(ctx, "h1", transferRecord{
		JTI:          "j1",
		Sub:          "alice",
		Entitlements: []string{"functions:/api/v1/files:read"},
		Target:       TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
	}, time.Minute)

	// First redemption succeeds and re-dispatches to the bound target.
	req := httptest.NewRequest("GET", "/-/transfer/h1", nil)
	req.SetPathValue("handle", "h1")
	rw := httptest.NewRecorder()
	hh.TransferGet(rw, req)
	g.Expect(rw.Code).To(Equal(http.StatusOK))
	g.Expect(rw.Body.String()).To(Equal("FILEBYTES"))
	g.Expect(sawPath).To(Equal("/api/v1/files/abc/content"))
	g.Expect(sawEnts).To(Equal([]string{"functions:/api/v1/files:read"}))

	// Second redemption is spent -> 410 (single-use).
	req2 := httptest.NewRequest("GET", "/-/transfer/h1", nil)
	req2.SetPathValue("handle", "h1")
	rw2 := httptest.NewRecorder()
	hh.TransferGet(rw2, req2)
	g.Expect(rw2.Code).To(Equal(http.StatusGone))
}

func TestTransferGet_UnknownHandle410(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{cacheManager: mgr, Mux: http.NewServeMux()}
	req := httptest.NewRequest("GET", "/-/transfer/nope", nil)
	req.SetPathValue("handle", "nope")
	rw := httptest.NewRecorder()
	hh.TransferGet(rw, req)
	g.Expect(rw.Code).To(Equal(http.StatusGone))
}

func TestTransferHandler_GatedOnPolicy(t *testing.T) {
	g := NewWithT(t)
	onMux := http.NewServeMux()
	(&HostHandler{authConfig: &auth.Config{MintTokenURLDelivery: true}}).transferHandler(onMux, nil)
	g.Expect(patternRegistered(onMux, transferPath)).To(BeTrue())

	offMux := http.NewServeMux()
	(&HostHandler{authConfig: &auth.Config{MintTokenURLDelivery: false}}).transferHandler(offMux, nil)
	g.Expect(patternRegistered(offMux, transferPath)).To(BeFalse())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run 'TestTransferGet|TestTransferHandler_GatedOnPolicy' -v`
Expected: FAIL — undefined `TransferGet` / `transferHandler` / `transferPath`.

- [ ] **Step 3: Implement the redemption route**

Append to `internal/host/transfer.go` (add imports `"strings"`, `"github.com/kdex-tech/host-manager/internal/auth"`, and `ko "..."` for `ko.PathInfo` — copy the alias used by the sibling `*Handler` methods in `handlers.go`):

```go
// transferPath is the redemption route for URL-delivered capabilities.
const transferPath = "/-/transfer/{handle}"

// transferHandler registers the redemption route, but only when URL delivery is
// enabled — a disabled host has no /-/transfer surface at all.
func (hh *HostHandler) transferHandler(mux *http.ServeMux, _ map[string]ko.PathInfo) {
	if hh.authConfig == nil || !hh.authConfig.MintTokenURLDelivery {
		return
	}
	mux.HandleFunc("GET "+transferPath, hh.TransferGet)
}

// TransferGet redeems a /-/transfer/<handle> capability: resolve the handle,
// spend one budget unit, inject the stored identity, and re-dispatch the bound
// target through the mux (which runs the proxy identity gate + per-op security
// against the injected entitlements). All non-redeemable cases return an
// identical 410 to preserve anti-enumeration.
func (hh *HostHandler) TransferGet(w http.ResponseWriter, r *http.Request) {
	gone := func() { http.Error(w, "This transfer link is no longer valid.", http.StatusGone) }

	ctx := r.Context()
	rec, ok := hh.loadTransferRecord(ctx, r.PathValue("handle"))
	if !ok {
		gone()
		return
	}
	if !strings.EqualFold(r.Method, rec.Target.Method) {
		gone()
		return
	}
	c := hh.capCache()
	if c == nil {
		gone()
		return
	}
	if _, ok, err := c.DecrementIfPositive(ctx, "uses:"+rec.JTI); err != nil || !ok {
		gone() // spent / expired / missing counter -> fail-closed
		return
	}

	hh.mu.RLock()
	mux := hh.Mux
	hh.mu.RUnlock()
	if mux == nil {
		gone()
		return
	}

	ac := auth.AuthContext{"sub": rec.Sub, "entitlements": rec.Entitlements}
	r2 := r.Clone(auth.SetAuthContext(ctx, ac))
	r2.Method = rec.Target.Method
	r2.URL.Path = rec.Target.Path
	r2.URL.RawPath = ""
	r2.URL.RawQuery = "" // bound target only — recipient cannot append query params
	r2.RequestURI = ""
	mux.ServeHTTP(w, r2)
}
```

Confirm the `ko` import alias matches `handlers.go` (e.g. `ko "github.com/kdex-tech/host-manager/internal/openapi"` — copy whatever `handlers.go` uses for `ko.PathInfo`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/host/ -run 'TestTransferGet|TestTransferHandler_GatedOnPolicy' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/host/transfer.go internal/host/transfer_test.go
git commit -m "feat(minttoken): /-/transfer redemption route with re-dispatch (#151)"
```

---

## Task 7: Wire the route into the mux + advertise in the tool schema

**Files:**
- Modify: `internal/host/host.go` (system-handler registration block, ~line 765)
- Modify: `internal/host/mint_token.go` (`mintTokenDescriptor` ~line 268)
- Test: `internal/host/mint_token_test.go`

**Interfaces:**
- Consumes: `transferHandler` (Task 6).
- Produces: the `/-/transfer/{handle}` route on the live host mux; `delivery`/`target` in the advertised `mint_token` input schema.

- [ ] **Step 1: Write the failing test**

Append to `internal/host/mint_token_test.go`:

```go
func TestMintTokenDescriptor_AdvertisesURLDelivery(t *testing.T) {
	g := NewWithT(t)
	d := mintTokenDescriptor("")
	props := d["inputSchema"].(map[string]any)["properties"].(map[string]any)
	g.Expect(props).To(HaveKey("delivery"))
	g.Expect(props).To(HaveKey("target"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run TestMintTokenDescriptor_AdvertisesURLDelivery -v`
Expected: FAIL — `properties` has no `delivery`/`target` key.

- [ ] **Step 3: Extend the descriptor input schema**

In `mintTokenDescriptor` (`internal/host/mint_token.go`), add to the `properties` map (after `"uses"`):

```go
					"delivery": map[string]any{
						"type":        "string",
						"enum":        []string{"bearer", "url"},
						"description": "How to deliver the capability. \"bearer\" (default) returns a token. \"url\" returns a single-use, credential-less /-/transfer/<handle> download link and requires `target`.",
					},
					"target": map[string]any{
						"type":        "object",
						"description": "Required when delivery==\"url\": the single concrete operation the link performs. Download-only: method must be GET; path must be an absolute non-/-/ path (e.g. /api/v1/files/<id>/content).",
						"properties": map[string]any{
							"method": map[string]any{"type": "string", "enum": []string{"GET"}},
							"path":   map[string]any{"type": "string"},
						},
						"required": []string{"method", "path"},
					},
```

Append one sentence to the `description` string (the base one, before the `discoveryURL != ""` block):

```go
	description := "Mint a short-lived, attenuated capability token carrying a subset of your own entitlements, for off-context/credential-less use against the REST API. Returns { token, expires_at, entitlements, uses_remaining }; pass it as `Authorization: Bearer <token>`. Every entitlement you request must already be held by you — the mint attenuates, never escalates. Pass delivery:\"url\" with a target:{method:\"GET\",path} to instead receive a single-use, credential-less /-/transfer/<handle> download link (host policy permitting)."
```

- [ ] **Step 4: Register the route on the host mux**

In `internal/host/host.go`, in the block that registers system handlers (alongside `hh.apitokensHandler(mux, registeredPaths)`, ~line 765), add:

```go
	hh.transferHandler(mux, registeredPaths)
```

- [ ] **Step 5: Run tests + build**

Run: `go test ./internal/host/ -run TestMintTokenDescriptor_AdvertisesURLDelivery -v && go build ./...`
Expected: PASS; build succeeds.

- [ ] **Step 6: Commit**

```bash
git add internal/host/host.go internal/host/mint_token.go internal/host/mint_token_test.go
git commit -m "feat(minttoken): register /-/transfer route + advertise delivery/target in tools/list (#151)"
```

---

## Task 8: End-to-end integration + regression + anti-enum

**Files:**
- Test: `internal/host/transfer_test.go`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the end-to-end test**

Append to `internal/host/transfer_test.go` (add imports `"strings"`, `"time"` already present; `"github.com/golang-jwt/jwt/v5"` not needed):

```go
func TestURLDelivery_EndToEnd(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)

	mux := http.NewServeMux()
	served := 0
	mux.HandleFunc("GET /api/v1/files/", func(w http.ResponseWriter, r *http.Request) {
		served++
		_, _ = w.Write([]byte("BYTES"))
	})

	hh := &HostHandler{authConfig: testURLAuthConfig(t), cacheManager: mgr, Mux: mux}
	hh.transferHandler(mux, nil) // register /-/transfer on the same mux

	// Mint a URL capability.
	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"functions:/api/v1/files:read"},
		MintTokenRequest{
			Entitlements: []string{"functions:/api/v1/files:read"},
			Delivery:     "url",
			Target:       &TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
		}, "https://dev.example")
	g.Expect(err).ToNot(HaveOccurred())
	path := strings.TrimPrefix(res.URL, "https://dev.example")

	// Redeem through the registered route: streams the bytes once.
	rw := httptest.NewRecorder()
	mux.ServeHTTP(rw, httptest.NewRequest("GET", path, nil))
	g.Expect(rw.Code).To(Equal(http.StatusOK))
	g.Expect(rw.Body.String()).To(Equal("BYTES"))
	g.Expect(served).To(Equal(1))

	// Second redeem: single-use spent -> 410, backend not hit again.
	rw2 := httptest.NewRecorder()
	mux.ServeHTTP(rw2, httptest.NewRequest("GET", path, nil))
	g.Expect(rw2.Code).To(Equal(http.StatusGone))
	g.Expect(served).To(Equal(1))
}

func TestBearerDelivery_Unchanged(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"functions:/api/v1/files:read"},
		MintTokenRequest{Entitlements: []string{"functions:/api/v1/files:read"}}, "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Token).ToNot(BeEmpty())
	g.Expect(res.URL).To(BeEmpty())
}
```

- [ ] **Step 2: Run the full package test suite**

Run: `go test ./internal/host/ ./internal/auth/ -v 2>&1 | tail -40`
Expected: PASS — all new tests plus the existing mint_token/auth suites (regression).

- [ ] **Step 3: Lint the whole module from the workspace root**

Run:
```bash
cd .. && make lint
```
Expected: no lint errors introduced (gofmt/vet/golangci-lint clean for the touched files).

- [ ] **Step 4: Commit**

```bash
cd kdex-host-manager
git add internal/host/transfer_test.go
git commit -m "test(minttoken): end-to-end url delivery + bearer regression (#151)"
```

---

## Self-Review

**Spec coverage** (against `docs/superpowers/specs/2026-07-21-capability-url-delivery-design.md`):
- §Mint surface (`delivery`/`target`/`url`, reuse clamps, force uses=1) → Tasks 3, 5. ✔
- §Transfer handle (server-side, claims-only, cap cache, TTL, revoke-by-delete) → Task 4. ✔
- §Redemption route (lookup → method guard → decrement → AuthContext inject → re-dispatch) → Task 6. ✔
- §Policy (`urlDelivery` CRD bool + propagation + `applyMintTokenPolicy`) → Tasks 1, 2, 7. ✔
- §Security (attenuation unchanged, reserved-`/-/` guard, no credential in URL, fail-closed, spend-on-attempt) → Tasks 3, 5, 6. ✔
- §Error handling (uniform 410, feature-off/target/reserved mint errors) → Tasks 5, 6. ✔
- §Testing (mint, handle lifecycle, redemption, opt-in gating, anti-enum, integration, bearer regression) → Tasks 2, 4, 5, 6, 8. ✔
- **Deliberately deferred, per spec §Security "best-effort":** the mint-time fail-fast target authorization pre-check is **not** implemented — the redeem-time proxy identity gate (`404`) is the guaranteed backstop, and the spec allows skipping the pre-check. No task; documented here so it isn't mistaken for a gap.
- **Out of scope (spec §Scope):** upload-by-URL, bearer-form in-JWT caveats, object-path/content-hash binding — no tasks, by design.

**Type consistency:** `mintCapabilityToken(...baseURL string)` and `writeMintTokenRPC(w, r, ...)` new signatures are updated at every call site (Task 5 Steps 4-5). `transferRecord{JTI,Sub,Entitlements,Target}`, `TransferTarget{Method,Path}`, `transferPath`, `transferKeyPrefix`, `capCache`, `storeTransferRecord`/`loadTransferRecord`, `newTransferHandle`, `transferBaseURL`, `errNoCache`, `TransferGet`, `transferHandler` are named identically across Tasks 3-8.

**Placeholder scan:** no TBD/TODO; every code step shows complete code; every run step shows the command + expected result.
