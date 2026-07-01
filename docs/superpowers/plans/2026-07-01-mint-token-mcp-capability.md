# `mint_token` MCP Capability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an MCP tool `mint_token` that lets an MCP connector mint a short-lived, attenuated, (optionally) bounded-use host-audience JWT carrying a subset of the caller's own entitlements, for off-context / credential-less use against the knowdb + host-manager REST surface.

**Architecture:** host-manager (the Authorization Server) augments its own OAuth2-protected MCP resource: it intercepts `tools/call {name:"mint_token"}` on that route and handles it locally (never forwarding to knowdb), and splices the tool descriptor into `tools/list` responses. The minted token is a host-audience JWT whose narrowed `entitlements` claim is trusted verbatim by the existing inbound-JWT path and enforced end-to-end by the existing proxy gate + knowdb. Attenuation uses a new *directional* dominance predicate in kdex-entitlements. Bounded-use is a jti-keyed Valkey counter decremented atomically in inbound middleware.

**Tech Stack:** Go 1.26.0; `github.com/golang-jwt/jwt/v5`; `github.com/kdex-tech/entitlements/go`; `github.com/valkey-io/valkey-go`; kubebuilder CRDs (`kdex.dev/crds`); test frameworks already in-repo: `github.com/onsi/gomega` (host package) and `github.com/stretchr/testify` (cache package).

## Global Constraints

- Go version is pinned to **1.26.0** across kdex-crds / kdex-entitlements / kdex-host-manager — do not change `go` directives.
- The minted capability token MUST be a **host-audience JWT** (`aud = Config.Audience`, `iss = Config.Issuer`), signed with the host's active key pair. Never a PASETO PAT, never a function/FAT audience.
- Attenuation is **directional**: a wildcard resourceName is honored ONLY on the *held* side. Never reuse `EntitlementsChecker.VerifyEntitlements` for attenuation.
- One Kubernetes resource concept per file; 2-space YAML indentation (for any manifest/sample).
- CRD changes propagate from the workspace root via `./updateCrdUsage.sh -t` (bumps kdex-crds tag, updates host-manager + nexus-manager `go.mod`). Never hand-edit the `replace`/`require` for `kdex.dev/crds`.
- **Two-commit CRD rule:** land a CRD field before any manifest/terraform uses it (plan-time schema validation runs against the live cluster). Host-manager Go code may consume the new Go type in the same series once `go.mod` is bumped.
- Commit inside the sub-repo where the change lives (kdex-entitlements, kdex-crds, or kdex-host-manager). Work happens on branch `feat/mint-token-mcp-280` in kdex-host-manager; create matching short-lived branches in the other repos.
- Every commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- After host-manager code changes, run `make test` (and `make lint`) inside `kdex-host-manager` before marking a task done.

## File Structure

**kdex-entitlements (repo: `kdex-entitlements`, module `github.com/kdex-tech/entitlements/go`)**
- Modify: `go/entitlements.go` — add exported `Dominates` and `VerifyAttenuation`.
- Modify: `go/entitlements_test.go` — table tests for both.

**kdex-crds (repo: `kdex-crds`, module `kdex.dev/crds`)**
- Modify: `api/v1alpha1/types.go` — add `MintToken` struct; add `MintToken *MintToken` field to `Auth`.
- Generated (by `make manifests generate`): `config/crd/bases/*kdexhost*.yaml`, `api/v1alpha1/zz_generated.deepcopy.go`, `CRD_REFERENCE.md`.

**kdex-host-manager (repo: `kdex-host-manager`, module `github.com/kdex-tech/host-manager`)**
- Modify: `internal/auth/config.go` — plumb `MintToken` policy from `Auth` into `Config`.
- Create: `internal/host/mint_token.go` — request/result types, `mintCapabilityToken`, JSON-RPC types, `handleMintTokenRPC`, `spliceMintTokenDescriptor`.
- Create: `internal/host/mint_token_test.go` — unit tests for attenuation, token shape, interception.
- Modify: `internal/host/proxy.go` — wire `fh.mintTokenEnabled`; intercept `tools/call` before `proxy.ServeHTTP`; mark `tools/list` for `ModifyResponse` splice.
- Modify: `internal/host/types.go` — add `mintTokenEnabled bool` to `KDexFunctionHandler`.
- Modify: `internal/cache/cache.go` — add `DecrementIfPositive` to the `Cache` interface.
- Modify: `internal/cache/memory.go` + `internal/cache/memory_test.go` — in-memory impl + tests.
- Modify: `internal/cache/valkey.go` + `internal/cache/valkey_test.go` — Lua impl + tests.
- Modify: `internal/auth/middleware.go` — decrement the jti counter for marker-claim tokens; fail-closed.
- Create: `internal/auth/middleware_capuses_test.go` — decrement/exhaustion/fail-closed tests.

---

## Phase 0 — kdex-entitlements: directional attenuation predicate

### Task 1: `Dominates` + `VerifyAttenuation` in kdex-entitlements (go)

**Files:**
- Modify: `go/entitlements.go` (repo `kdex-entitlements`)
- Test: `go/entitlements_test.go`

**Interfaces:**
- Produces: `func Dominates(held, requested string) bool`; `func VerifyAttenuation(held, requested []string) (offender string, ok bool)` in package `entitlements`.

- [ ] **Step 1: Write the failing test**

Add to `go/entitlements_test.go`:

```go
func TestDominates(t *testing.T) {
	cases := []struct {
		held, requested string
		want            bool
	}{
		{"vector_stores::write", "vector_stores:X:write", true},   // held wildcard dominates specific
		{"vector_stores:*:write", "vector_stores:X:write", true},  // explicit * on held side
		{"vector_stores:X:write", "vector_stores:*:write", false}, // specific CANNOT widen to wildcard
		{"vector_stores:X:write", "vector_stores::write", false},  // specific CANNOT widen to empty(*)
		{"vector_stores:X:write", "vector_stores:X:write", true},  // exact
		{"vector_stores:X:write", "vector_stores:Y:write", false}, // different resourceName
		{"functions:/api/v1/files:all", "functions:/api/v1/files:write", true}, // verb all dominates
		{"functions:/api/v1/files:write", "functions:/api/v1/files:all", false}, // requested all not dominated
		{"functions:/x:write", "pages:/x:write", false},           // different resource
		{"functions:/api/v1/files:read", "functions:/api/v1/files:write", false}, // different verb
		{"admin", "admin", true},                                   // opaque exact
		{"admin", "billing", false},                                // opaque mismatch
		{"functions:read", "functions:/api/v1/files:read", true},   // short held == functions:*:read
	}
	for _, c := range cases {
		if got := Dominates(c.held, c.requested); got != c.want {
			t.Errorf("Dominates(%q,%q)=%v want %v", c.held, c.requested, got, c.want)
		}
	}
}

func TestVerifyAttenuation(t *testing.T) {
	held := []string{"functions:/api/v1/files:write", "vector_stores::read"}
	if off, ok := VerifyAttenuation(held, []string{"functions:/api/v1/files:write", "vector_stores:X:read"}); !ok {
		t.Fatalf("expected ok, got offender %q", off)
	}
	off, ok := VerifyAttenuation(held, []string{"vector_stores:X:read", "vector_stores:*:read"})
	if ok || off != "vector_stores:*:read" {
		t.Fatalf("expected reject on wildcard widen, got ok=%v offender=%q", ok, off)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./... -run 'TestDominates|TestVerifyAttenuation' -v`
Expected: FAIL — `undefined: Dominates`, `undefined: VerifyAttenuation`.

- [ ] **Step 3: Write minimal implementation**

Append to `go/entitlements.go` (package `entitlements`; `strings` is already imported):

```go
// Dominates reports whether the held entitlement is equal to or BROADER than
// the requested one under the kdex-entitlements grammar. This is the predicate
// for attenuation (minting a token that carries a subset of the caller's
// authority). Unlike request-time matching (entitlementMatches), a wildcard
// resourceName is honored ONLY on the held side: a specific grant cannot
// dominate a wildcard request, so a mint can never broaden authority.
//
// Opaque scopes (no ':') dominate only by exact match.
func Dominates(held, requested string) bool {
	if held == requested {
		return true
	}

	hp := strings.Split(held, ":")
	if len(hp) == 2 { // short form <resource>:<verb> == <resource>:*:<verb>
		hp = []string{hp[0], "", hp[1]}
	}
	rp := strings.Split(requested, ":")
	if len(rp) == 2 {
		rp = []string{rp[0], "", rp[1]}
	}

	// Opaque or malformed: only exact match (handled above) dominates.
	if len(hp) != 3 || len(rp) != 3 {
		return false
	}

	// Resource type must match.
	if hp[0] != rp[0] {
		return false
	}

	// Verb: held "all" dominates any; otherwise verbs must match. A requested
	// "all" is NOT dominated by a specific held verb.
	if hp[2] != "all" && hp[2] != rp[2] {
		return false
	}

	// resourceName: a wildcard is honored ONLY on the held side.
	if hp[1] == "" || hp[1] == "*" {
		return true
	}
	return hp[1] == rp[1]
}

// VerifyAttenuation returns ("", true) when every requested entitlement is
// dominated by at least one held entitlement. Otherwise it returns the first
// requested entitlement that no held entitlement dominates, and false.
func VerifyAttenuation(held, requested []string) (offender string, ok bool) {
	for _, req := range requested {
		dominated := false
		for _, h := range held {
			if Dominates(h, req) {
				dominated = true
				break
			}
		}
		if !dominated {
			return req, false
		}
	}
	return "", true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd go && go test ./... -v`
Expected: PASS (new tests + existing suite).

- [ ] **Step 5: Commit, tag, note the version**

```bash
cd go && go vet ./... && cd ..
git add go/entitlements.go go/entitlements_test.go
git commit -m "feat: add directional Dominates/VerifyAttenuation for attenuation

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
# Tag the go submodule (tags are prefixed 'go/' — see existing 'go/v0.2.0').
git tag go/v0.2.1
git push origin HEAD go/v0.2.1
```

Record `go/v0.2.1` — Task 3 consumes it.

---

## Phase 1 — CRD field, policy plumbing, stateless mint, interception

### Task 2: Add `MintToken` to the KDexHost CRD

**Files:**
- Modify: `api/v1alpha1/types.go` (repo `kdex-crds`)
- Generated: `config/crd/bases/*kdexhost*.yaml`, `api/v1alpha1/zz_generated.deepcopy.go`, `CRD_REFERENCE.md`

**Interfaces:**
- Produces: Go type `kdexv1alpha1.MintToken`; field `Auth.MintToken *MintToken`.

- [ ] **Step 1: Add the struct + field**

In `api/v1alpha1/types.go`, add a new struct near the other auth sub-types:

```go
// MintToken configures the host's `mint_token` MCP capability — the
// caller-driven minting of short-lived, attenuated, optionally bounded-use
// host-audience JWTs surfaced on OAuth2-protected MCP functions. When nil or
// enabled=false the tool is not advertised and mint calls are rejected.
type MintToken struct {
	// enabled turns the mint_token capability on for this host.
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled" protobuf:"varint,1,opt,name=enabled"`

	// ttlCapSeconds is the hard server-side ceiling (and default) applied to a
	// requested ttl_seconds. Defaults to 60 when zero.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=60
	// +kubebuilder:validation:Minimum=1
	TTLCapSeconds int `json:"ttlCapSeconds,omitempty" protobuf:"varint,2,opt,name=ttlCapSeconds"`

	// usesCap is the hard server-side ceiling applied to a requested uses count.
	// Defaults to 32 when zero. A value of 1 forces single-use for all grants.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=32
	// +kubebuilder:validation:Minimum=1
	UsesCap int `json:"usesCap,omitempty" protobuf:"varint,3,opt,name=usesCap"`

	// destructiveVerbs lists entitlement verbs whose presence in a requested
	// entitlement forces uses=1 and the shortest ttl. Defaults to
	// ["delete","own"] when nil.
	// +kubebuilder:validation:Optional
	DestructiveVerbs []string `json:"destructiveVerbs,omitempty" protobuf:"bytes,4,rep,name=destructiveVerbs"`
}
```

Then add to the `Auth` struct (alongside `APIToken`, `DynamicClientRegistration`):

```go
	// mintToken configures the mint_token MCP capability. Nil/absent ⇒ off.
	// +kubebuilder:validation:Optional
	MintToken *MintToken `json:"mintToken,omitempty" protobuf:"bytes,10,opt,name=mintToken"`
```

(Use protobuf field number `10` — the next free number on `Auth`; verify none of the existing fields already use it and bump if needed.)

- [ ] **Step 2: Regenerate + verify it compiles**

Run:
```bash
cd /path/to/kdex-crds && make manifests generate docs
go build ./...
```
Expected: `zz_generated.deepcopy.go` gains `MintToken` DeepCopy methods; the KDexHost CRD YAML gains `spec.auth.mintToken`; build succeeds.

- [ ] **Step 3: Commit inside kdex-crds**

```bash
git add api/v1alpha1/types.go api/v1alpha1/zz_generated.deepcopy.go config/crd/bases CRD_REFERENCE.md
git commit -m "feat: add spec.auth.mintToken to KDexHost

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: Propagate the CRD tag to host-manager**

From the **workspace root**:
```bash
./updateCrdUsage.sh -t
```
Expected: kdex-crds patch tag bumped + pushed; `kdex-host-manager/go.mod` + `go.sum` updated to the new `kdex.dev/crds` tag and pushed. Confirm `kdexv1alpha1.MintToken` is now importable:
```bash
cd kdex-host-manager && go build ./... 2>&1 | head
```

### Task 3: Bump entitlements dep + plumb MintToken policy into Config

**Files:**
- Modify: `kdex-host-manager/go.mod`, `go.sum`
- Modify: `internal/auth/config.go`
- Test: `internal/auth/config_test.go` (create if absent; else append)

**Interfaces:**
- Consumes: `entitlements.VerifyAttenuation` (Task 1, `go/v0.2.1`); `kdexv1alpha1.MintToken` (Task 2).
- Produces: `Config` fields `MintTokenEnabled bool`, `MintTokenTTLCap time.Duration`, `MintTokenUsesCap int`, `MintTokenDestructiveVerbs []string`.

- [ ] **Step 1: Bump the entitlements dependency**

Run inside `kdex-host-manager`:
```bash
go get github.com/kdex-tech/entitlements/go@v0.2.1
go mod tidy
go build ./... 2>&1 | head -30
```
Expected: builds. If the jump from v0.1.22 surfaces compile errors from unrelated API changes, fix call sites minimally (the host uses `NewEntitlementsChecker`, `VerifyResourceParsedEntitlements`, `ParseRequirements`, `GetParsedEntitlements` — confirm signatures unchanged) before proceeding.

- [ ] **Step 2: Write the failing test**

Add to `internal/auth/config_test.go`:

```go
func TestBuild_MintTokenPolicy(t *testing.T) {
	g := NewWithT(t)
	cb := newTestConfigBuilder(t) // helper that wires KeyLoader + Audience + Issuer (mirror existing config tests)
	auth := &kdexv1alpha1.Auth{
		JWT: kdexv1alpha1.JWT{},
		MintToken: &kdexv1alpha1.MintToken{
			Enabled: true, TTLCapSeconds: 45, UsesCap: 8,
			DestructiveVerbs: []string{"delete"},
		},
	}
	cfg, err := cb.Build(auth)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cfg.MintTokenEnabled).To(BeTrue())
	g.Expect(cfg.MintTokenTTLCap).To(Equal(45 * time.Second))
	g.Expect(cfg.MintTokenUsesCap).To(Equal(8))
	g.Expect(cfg.MintTokenDestructiveVerbs).To(Equal([]string{"delete"}))
}
```

If the auth package has no existing config-builder test helper, construct the builder inline the way `Build` is exercised elsewhere (search for existing `ConfigBuilder{}` usage in tests and mirror it; provide a `KeyLoader` returning a dev key pair via `keys.GenerateDevmodeKeyPair`-style helper already used by other tests).

- [ ] **Step 2b: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestBuild_MintTokenPolicy -v`
Expected: FAIL — `cfg.MintTokenEnabled undefined`.

- [ ] **Step 3: Add Config fields + plumb in Build**

In `internal/auth/config.go`, add to the `Config` struct:

```go
	MintTokenEnabled          bool
	MintTokenTTLCap           time.Duration
	MintTokenUsesCap          int
	MintTokenDestructiveVerbs []string
```

In `ConfigBuilder.Build`, inside the `if auth != nil {` block (after `cfg.CookieName = ...`), add:

```go
		if auth.MintToken != nil && auth.MintToken.Enabled {
			cfg.MintTokenEnabled = true
			ttlCap := auth.MintToken.TTLCapSeconds
			if ttlCap <= 0 {
				ttlCap = 60
			}
			cfg.MintTokenTTLCap = time.Duration(ttlCap) * time.Second
			usesCap := auth.MintToken.UsesCap
			if usesCap <= 0 {
				usesCap = 32
			}
			cfg.MintTokenUsesCap = usesCap
			cfg.MintTokenDestructiveVerbs = auth.MintToken.DestructiveVerbs
			if cfg.MintTokenDestructiveVerbs == nil {
				cfg.MintTokenDestructiveVerbs = []string{"delete", "own"}
			}
		}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/auth/ -run TestBuild_MintTokenPolicy -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/auth/config.go internal/auth/config_test.go
git commit -m "feat: plumb spec.auth.mintToken policy into auth.Config (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 4: `mintCapabilityToken` — attenuation + host-audience JWT (stateless)

**Files:**
- Create: `internal/host/mint_token.go`
- Test: `internal/host/mint_token_test.go`

**Interfaces:**
- Consumes: `entitlements.VerifyAttenuation`; `sign.NewSigner`; `hh.authConfig` (`*auth.Config`, fields `Audience`, `Issuer`, `ActivePair`, `MintTokenEnabled`, `MintTokenTTLCap`, `MintTokenUsesCap`, `MintTokenDestructiveVerbs`).
- Produces:
  - `type MintTokenRequest struct { Entitlements []string; TTLSeconds int; Uses int }`
  - `type MintTokenResult struct { Token string; ExpiresAt int64; Entitlements []string; UsesRemaining int }`
  - `const capUsesClaim = "kdx_cap"`
  - `func (hh *HostHandler) mintCapabilityToken(ctx context.Context, sub string, held []string, req MintTokenRequest) (MintTokenResult, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/host/mint_token_test.go`:

```go
package host

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	. "github.com/onsi/gomega"
)

func testAuthConfigForMint(t *testing.T) *auth.Config {
	t.Helper()
	kp := keys.GenerateDevmodeKeyPair() // ECDSA P-256 dev pair
	return &auth.Config{
		Audience:                  "https://dev.example",
		Issuer:                    "https://dev.example",
		ActivePair:                kp.ActiveKey(),
		MintTokenEnabled:          true,
		MintTokenTTLCap:           60 * time.Second,
		MintTokenUsesCap:          32,
		MintTokenDestructiveVerbs: []string{"delete", "own"},
	}
}

func TestMintCapabilityToken_AttenuatesAndSignsHostAudience(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	held := []string{"functions:/api/v1/files:write", "functions:/api/v1/files:read"}

	res, err := hh.mintCapabilityToken(context.Background(), "alice", held, MintTokenRequest{
		Entitlements: []string{"functions:/api/v1/files:write"},
		TTLSeconds:   30,
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Entitlements).To(Equal([]string{"functions:/api/v1/files:write"}))

	// Parse back with the active public key; assert host audience + claim.
	var claims jwt.MapClaims
	_, perr := jwt.ParseWithClaims(res.Token, &claims, func(*jwt.Token) (any, error) {
		return hh.authConfig.ActivePair.Private.Public(), nil
	}, jwt.WithAudience("https://dev.example"), jwt.WithIssuer("https://dev.example"))
	g.Expect(perr).ToNot(HaveOccurred())
	g.Expect(claims["sub"]).To(Equal("alice"))
	g.Expect(claims["entitlements"]).To(ContainElement("functions:/api/v1/files:write"))
	g.Expect(claims[capUsesClaim]).To(BeTrue())
}

func TestMintCapabilityToken_RejectsOverBroad(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	held := []string{"functions:/api/v1/files:write"}

	_, err := hh.mintCapabilityToken(context.Background(), "alice", held, MintTokenRequest{
		Entitlements: []string{"functions:/api/v1/files:*"},
	})
	g.Expect(err).To(MatchError(ContainSubstring("functions:/api/v1/files:*")))
}

func TestMintCapabilityToken_ClampsTTL(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"pages:/:read"}, MintTokenRequest{Entitlements: []string{"pages:/:read"}, TTLSeconds: 99999})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.ExpiresAt).To(BeNumerically("<=", time.Now().Add(61*time.Second).Unix()))
}
```

(If `keys.GenerateDevmodeKeyPair` is not the exact helper name, use whatever dev-key helper the existing key/auth tests use — search `keys` package for the ECDSA P-256 generator.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run TestMintCapabilityToken -v`
Expected: FAIL — undefined `MintTokenRequest`, `mintCapabilityToken`, `capUsesClaim`.

- [ ] **Step 3: Write the implementation**

Create `internal/host/mint_token.go`:

```go
package host

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/sign"
)

// capUsesClaim marks a JWT as a bounded-use capability minted by mint_token.
// The inbound middleware decrements the jti-keyed use counter only for tokens
// carrying this claim; ordinary session/FAT tokens never carry it.
const capUsesClaim = "kdx_cap"

// MintTokenRequest is the argument shape of the mint_token MCP tool.
type MintTokenRequest struct {
	Entitlements []string `json:"entitlements"`
	TTLSeconds   int      `json:"ttl_seconds,omitempty"`
	Uses         int      `json:"uses,omitempty"`
}

// MintTokenResult is the mint_token success payload.
type MintTokenResult struct {
	Token         string   `json:"token"`
	ExpiresAt     int64    `json:"expires_at"`
	Entitlements  []string `json:"entitlements"`
	UsesRemaining int      `json:"uses_remaining"`
}

// hasDestructiveVerb reports whether any requested entitlement's verb is in the
// configured destructive set.
func hasDestructiveVerb(requested, destructive []string) bool {
	for _, e := range requested {
		parts := strings.Split(e, ":")
		verb := parts[len(parts)-1]
		for _, d := range destructive {
			if verb == d {
				return true
			}
		}
	}
	return false
}

// mintCapabilityToken verifies requested ⊆ held (directional attenuation),
// clamps ttl/uses to the host policy, and signs a short-lived HOST-AUDIENCE
// JWT whose entitlements claim is exactly the requested (attenuated) set. The
// caller (interception layer) supplies sub + held from the request auth context.
//
// Phase 1: the token is a stateless windowed JWT. `Uses` is clamped and
// reflected in UsesRemaining but no counter is provisioned yet (Phase 2 adds
// the jti-keyed Valkey counter and the middleware decrement). The capUsesClaim
// marker is always set so Phase 2 activates without re-minting semantics.
func (hh *HostHandler) mintCapabilityToken(ctx context.Context, sub string, held []string, req MintTokenRequest) (MintTokenResult, error) {
	cfg := hh.authConfig
	if cfg == nil || !cfg.MintTokenEnabled {
		return MintTokenResult{}, fmt.Errorf("mint_token is not enabled on this host")
	}
	if sub == "" {
		return MintTokenResult{}, fmt.Errorf("mint_token requires an authenticated caller")
	}
	if len(req.Entitlements) == 0 {
		return MintTokenResult{}, fmt.Errorf("mint_token requires at least one entitlement")
	}

	// Attenuation: every requested entitlement must be dominated by the held set.
	if offender, ok := entitlements.VerifyAttenuation(held, req.Entitlements); !ok {
		return MintTokenResult{}, fmt.Errorf("entitlement not held by caller: %s", offender)
	}

	// Clamp ttl.
	ttl := cfg.MintTokenTTLCap
	if req.TTLSeconds > 0 {
		reqTTL := time.Duration(req.TTLSeconds) * time.Second
		if reqTTL < ttl {
			ttl = reqTTL
		}
	}

	// Clamp uses; destructive verbs force single-use + shortest ttl.
	uses := req.Uses
	if uses <= 0 {
		uses = 1
	}
	if uses > cfg.MintTokenUsesCap {
		uses = cfg.MintTokenUsesCap
	}
	if hasDestructiveVerb(req.Entitlements, cfg.MintTokenDestructiveVerbs) {
		uses = 1
		if ttl > 10*time.Second {
			ttl = 10 * time.Second
		}
	}

	signer, err := sign.NewSigner(cfg.Audience, ttl, cfg.Issuer, &cfg.ActivePair.Private, cfg.ActivePair.KeyId, nil)
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint signer: %w", err)
	}

	claims := jwt.MapClaims{
		"sub":          sub,
		"entitlements": req.Entitlements,
		capUsesClaim:   true,
	}
	token, err := signer.Sign(claims)
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint sign: %w", err)
	}

	return MintTokenResult{
		Token:         token,
		ExpiresAt:     time.Now().Add(ttl).Unix(),
		Entitlements:  req.Entitlements,
		UsesRemaining: uses,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/host/ -run TestMintCapabilityToken -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/host/mint_token.go internal/host/mint_token_test.go
git commit -m "feat: mintCapabilityToken — attenuated host-audience JWT (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 5: JSON-RPC `tools/call` interception for `mint_token`

**Files:**
- Modify: `internal/host/mint_token.go` (add JSON-RPC types + handler)
- Modify: `internal/host/mint_token_test.go`

**Interfaces:**
- Consumes: `mintCapabilityToken` (Task 4); `auth.GetAuthContext`.
- Produces:
  - `func isMintTokenCall(body []byte) (id json.RawMessage, args MintTokenRequest, matched bool)`
  - `func (hh *HostHandler) writeMintTokenRPC(w http.ResponseWriter, id json.RawMessage, sub string, held []string, args MintTokenRequest)`

- [ ] **Step 1: Write the failing test**

Add to `internal/host/mint_token_test.go`:

```go
func TestIsMintTokenCall(t *testing.T) {
	g := NewWithT(t)
	body := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"mint_token","arguments":{"entitlements":["pages:/:read"],"ttl_seconds":30}}}`)
	id, args, matched := isMintTokenCall(body)
	g.Expect(matched).To(BeTrue())
	g.Expect(string(id)).To(Equal("7"))
	g.Expect(args.Entitlements).To(Equal([]string{"pages:/:read"}))
	g.Expect(args.TTLSeconds).To(Equal(30))

	_, _, m2 := isMintTokenCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_atoms"}}`))
	g.Expect(m2).To(BeFalse())

	_, _, m3 := isMintTokenCall([]byte(`[{"jsonrpc":"2.0"}]`)) // batch passthrough
	g.Expect(m3).To(BeFalse())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run TestIsMintTokenCall -v`
Expected: FAIL — `undefined: isMintTokenCall`.

- [ ] **Step 3: Add JSON-RPC types + interception helpers**

Append to `internal/host/mint_token.go` (add `encoding/json` and `net/http` to imports):

```go
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// isMintTokenCall returns the request id, parsed arguments, and true when body
// is a single JSON-RPC tools/call for the mint_token tool. Batch (array) bodies
// and any other method/tool return matched=false (passthrough). MCP revision
// 2025-06-18 removed batching, so only the single-object shape is intercepted.
func isMintTokenCall(body []byte) (json.RawMessage, MintTokenRequest, bool) {
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") {
		return nil, MintTokenRequest{}, false
	}
	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, MintTokenRequest{}, false
	}
	if req.Method != "tools/call" || req.Params.Name != "mint_token" {
		return nil, MintTokenRequest{}, false
	}
	var args MintTokenRequest
	if len(req.Params.Arguments) > 0 {
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return req.ID, MintTokenRequest{}, true // matched but bad args; handler emits error
		}
	}
	return req.ID, args, true
}

// mcpToolResult wraps a value as an MCP tools/call result (structuredContent +
// a text content block, per MCP tools/call response shape).
func mcpToolResult(v any) map[string]any {
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": mustJSON(v)}},
		"structuredContent": v,
		"isError":           false,
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// writeMintTokenRPC executes the mint and writes a JSON-RPC response. Attenuation
// / policy failures are returned as an MCP tool error result (isError=true) with
// HTTP 200, matching how MCP tools surface domain errors.
func (hh *HostHandler) writeMintTokenRPC(w http.ResponseWriter, id json.RawMessage, sub string, held []string, args MintTokenRequest) {
	w.Header().Set("Content-Type", "application/json")
	res, err := hh.mintCapabilityToken(context.Background(), sub, held, args)
	var payload jsonRPCResponse
	if err != nil {
		payload = jsonRPCResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		}}
	} else {
		payload = jsonRPCResponse{JSONRPC: "2.0", ID: id, Result: mcpToolResult(res)}
	}
	_ = json.NewEncoder(w).Encode(payload)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/host/ -run 'TestIsMintTokenCall|TestMintCapabilityToken' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/host/mint_token.go internal/host/mint_token_test.go
git commit -m "feat: JSON-RPC tools/call interception for mint_token (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 6: `tools/list` descriptor splice

**Files:**
- Modify: `internal/host/mint_token.go`
- Modify: `internal/host/mint_token_test.go`

**Interfaces:**
- Produces:
  - `func mintTokenDescriptor() map[string]any`
  - `func isToolsListCall(body []byte) bool`
  - `func spliceMintTokenDescriptor(respBody []byte) ([]byte, bool)`

- [ ] **Step 1: Write the failing test**

Add to `internal/host/mint_token_test.go`:

```go
func TestSpliceMintTokenDescriptor(t *testing.T) {
	g := NewWithT(t)
	resp := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_atoms"}]}}`)
	out, ok := spliceMintTokenDescriptor(resp)
	g.Expect(ok).To(BeTrue())

	var parsed jsonRPCResponse
	g.Expect(json.Unmarshal(out, &parsed)).To(Succeed())
	result := parsed.Result.(map[string]any)
	tools := result["tools"].([]any)
	g.Expect(tools).To(HaveLen(2))
	names := []string{tools[0].(map[string]any)["name"].(string), tools[1].(map[string]any)["name"].(string)}
	g.Expect(names).To(ContainElement("mint_token"))
	g.Expect(names).To(ContainElement("search_atoms"))
}

func TestIsToolsListCall(t *testing.T) {
	g := NewWithT(t)
	g.Expect(isToolsListCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))).To(BeTrue())
	g.Expect(isToolsListCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))).To(BeFalse())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run 'TestSpliceMintTokenDescriptor|TestIsToolsListCall' -v`
Expected: FAIL — undefined helpers.

- [ ] **Step 3: Implement the descriptor + splice**

Append to `internal/host/mint_token.go`:

```go
// mintTokenDescriptor is the MCP tools/list entry advertised for mint_token.
func mintTokenDescriptor() map[string]any {
	return map[string]any{
		"name": "mint_token",
		"description": "Mint a short-lived, attenuated capability token carrying a subset of your own entitlements, for off-context/credential-less use against the REST API. Returns { token, expires_at, entitlements, uses_remaining }.",
		"inputSchema": map[string]any{
			"type":     "object",
			"required": []string{"entitlements"},
			"properties": map[string]any{
				"entitlements": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "kdex-entitlements patterns (<resource>:<resourceName>:<verb>); each must be held by you.",
				},
				"ttl_seconds": map[string]any{"type": "integer", "description": "Requested lifetime; capped server-side."},
				"uses":        map[string]any{"type": "integer", "description": "Bounded use budget; capped server-side; destructive verbs force 1."},
			},
		},
	}
}

// isToolsListCall reports whether body is a single JSON-RPC tools/list request.
func isToolsListCall(body []byte) bool {
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") {
		return false
	}
	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}
	return req.Method == "tools/list"
}

// spliceMintTokenDescriptor appends the mint_token descriptor to result.tools of
// a tools/list JSON-RPC response. Returns (original, false) if the shape isn't a
// tools array (e.g. an SSE frame or an error response), so callers pass through.
func spliceMintTokenDescriptor(respBody []byte) ([]byte, bool) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return respBody, false
	}
	rawResult, ok := envelope["result"]
	if !ok {
		return respBody, false
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(rawResult, &result); err != nil {
		return respBody, false
	}
	rawTools, ok := result["tools"]
	if !ok {
		return respBody, false
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return respBody, false
	}
	descBytes, err := json.Marshal(mintTokenDescriptor())
	if err != nil {
		return respBody, false
	}
	tools = append(tools, descBytes)
	newTools, _ := json.Marshal(tools)
	result["tools"] = newTools
	newResult, _ := json.Marshal(result)
	envelope["result"] = newResult
	out, err := json.Marshal(envelope)
	if err != nil {
		return respBody, false
	}
	return out, true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/host/ -run 'TestSpliceMintTokenDescriptor|TestIsToolsListCall' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/host/mint_token.go internal/host/mint_token_test.go
git commit -m "feat: splice mint_token into tools/list (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 7: Wire interception into the function proxy handler

**Files:**
- Modify: `internal/host/types.go` (add `mintTokenEnabled` field)
- Modify: `internal/host/proxy.go` (set the flag; intercept in the handler; mark tools/list; splice in `ModifyResponse`)
- Test: `internal/host/mint_token_test.go` (end-to-end handler test with a stub upstream)

**Interfaces:**
- Consumes: `isMintTokenCall`, `writeMintTokenRPC`, `isToolsListCall`, `spliceMintTokenDescriptor`; `auth.GetAuthContext`; `KDexFunctionHandler.oauth2Protected`; `hh.authConfig.MintTokenEnabled`.
- Produces: `KDexFunctionHandler.mintTokenEnabled`; a context key `mintTokenListMarkerKey` used to signal `ModifyResponse`.

- [ ] **Step 1: Write the failing test (handler-level, stub upstream)**

Add to `internal/host/mint_token_test.go`:

```go
func TestReverseProxy_InterceptsMintTokenCall(t *testing.T) {
	g := NewWithT(t)

	// Stub upstream that must NEVER be called for a mint_token tools/call.
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	hh := newTestHostHandlerForProxy(t, testAuthConfigForMint(t)) // helper: sets authConfig, cacheManager, authChecker(nil-ok), authExchanger
	fn := newServiceBackedMCPFunction(t, upstream.URL)            // helper: KDexFunction with Status.URL=upstream, oauth2 on POST /api/v1/mcp
	handler := hh.reverseProxyHandler(fn, "https://dev.example")

	body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mint_token","arguments":{"entitlements":["pages:/:read"]}}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub": "alice", "entitlements": []any{"pages:/:read"},
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	g.Expect(upstreamHit).To(BeFalse())
	g.Expect(rr.Code).To(Equal(http.StatusOK))
	var resp jsonRPCResponse
	g.Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
	g.Expect(resp.Result).ToNot(BeNil())
}
```

Build `newTestHostHandlerForProxy` and `newServiceBackedMCPFunction` by mirroring the existing proxy tests (`internal/host/proxy_pat_test.go`, `internal/host/mcp_oauth2_e2e_test.go`): construct `HostHandler` with a real in-memory `cache.NewCacheManager("","",&ttl)`, an `auth.AuthorizationChecker` (or nil — the gate is skipped when `authChecker` is nil), the fake `authExchanger` those tests already define, and a `KDexFunction` whose `Status.URL` is the stub, `Spec.Backend.Type=Service`, and one `post` op on `/api/v1/mcp` declaring the `oauth2` scheme so `oauth2Protected` is set.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run TestReverseProxy_InterceptsMintTokenCall -v`
Expected: FAIL — upstream is hit / `mintTokenEnabled` undefined.

- [ ] **Step 3a: Add the handler field + context key**

In `internal/host/types.go`, add to `KDexFunctionHandler`:

```go
	// mintTokenEnabled opts this (oauth2-protected) MCP function into the AS
	// mint_token augmentation: tools/call name=mint_token is handled locally
	// and tools/list responses gain the mint_token descriptor. See #280.
	mintTokenEnabled bool
```

In `internal/host/mint_token.go`, add an unexported context key:

```go
type ctxKey int

const mintTokenListMarkerKey ctxKey = iota
```

- [ ] **Step 3b: Set the flag at handler-build time**

In `internal/host/proxy.go`, where `oauth2Protected` is set (right after the `if res, ok := hh.oauth2ProtectedResources()[fn.Spec.API.BasePath]; ok {` block, ~line 326-329), add:

```go
	if fh.oauth2Protected && hh.authConfig != nil && hh.authConfig.MintTokenEnabled {
		fh.mintTokenEnabled = true
	}
```

- [ ] **Step 3c: Intercept in the handler, before the proxy round-trip**

In `internal/host/proxy.go`, inside `fh.Handler` closure, immediately BEFORE the final `proxy.ServeHTTP(w, r)` call (after the `authChecker` gate block, ~line 473), add:

```go
		// mint_token AS-augmentation: peek the JSON-RPC body of an
		// oauth2-protected MCP function. A tools/call for mint_token is handled
		// locally (never forwarded); a tools/list is marked so ModifyResponse
		// can splice the descriptor. All other bodies pass through untouched.
		if fh.mintTokenEnabled && r.Method == http.MethodPost {
			body, rerr := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
			if rerr == nil {
				if id, args, matched := isMintTokenCall(body); matched {
					ac, _ := auth.GetAuthContext(r.Context())
					sub, _ := ac["sub"].(string)
					held := stringSliceFromClaim(ac["entitlements"])
					fh.hh.writeMintTokenRPC(w, id, sub, held, args) // see note on hh access below
					return
				}
				if isToolsListCall(body) {
					r = r.WithContext(context.WithValue(r.Context(), mintTokenListMarkerKey, true))
				}
			}
		}

		// Execute the proxy — runs WITHOUT holding hh.mu ...
		proxy.ServeHTTP(w, r)
```

Notes for the implementer:
- Add imports `bytes`, `io` to `proxy.go` (already imports `context`, `net/http`).
- `writeMintTokenRPC` is a `*HostHandler` method; call it via the `hh` receiver already in scope in `reverseProxyHandler` (the closure captures `hh`). Use `hh.writeMintTokenRPC(...)` directly — there is no `fh.hh`; the pseudo-reference above is illustrative. Replace with `hh.writeMintTokenRPC(w, id, sub, held, args)`.
- Add this helper to `internal/host/mint_token.go`:

```go
// stringSliceFromClaim coerces an entitlements claim (which arrives as
// []any after JSON round-trips, or []string when set in-process) to []string.
func stringSliceFromClaim(v any) []string {
	switch vv := v.(type) {
	case []string:
		return vv
	case []any:
		out := make([]string, 0, len(vv))
		for _, e := range vv {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
```

- [ ] **Step 3d: Splice tools/list in ModifyResponse**

In `internal/host/proxy.go`, extend the existing `ModifyResponse` (which currently only rewrites Set-Cookie). At the top of that function add:

```go
		if v, _ := resp.Request.Context().Value(mintTokenListMarkerKey).(bool); v &&
			strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			raw, rerr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if rerr == nil {
				if spliced, ok := spliceMintTokenDescriptor(raw); ok {
					raw = spliced
				}
				resp.Body = io.NopCloser(bytes.NewReader(raw))
				resp.ContentLength = int64(len(raw))
				resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(raw)))
			} else {
				resp.Body = io.NopCloser(bytes.NewReader(raw))
			}
		}
```

(`fmt` and `strings` are already imported in `proxy.go`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/host/ -run 'TestReverseProxy_InterceptsMintTokenCall|TestMintCapabilityToken|TestIsMintTokenCall|TestSpliceMintTokenDescriptor' -v`
Expected: PASS. Then full package: `go test ./internal/host/ -v` (no regressions).

- [ ] **Step 5: Commit**

```bash
git add internal/host/proxy.go internal/host/types.go internal/host/mint_token.go internal/host/mint_token_test.go
git commit -m "feat: wire mint_token interception into function proxy (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 8: Phase-1 verification pass (lint + full suite)

**Files:** none (verification only)

- [ ] **Step 1: Run the whole module**

Run: `cd kdex-host-manager && make test`
Expected: PASS.

- [ ] **Step 2: Lint**

Run: `make lint`
Expected: clean (fix any `gocyclo` growth in `reverseProxyHandler` by extracting the interception block into a helper `func (hh *HostHandler) tryInterceptMintToken(w, r, fh) (handled bool)` if the linter flags it — keep behavior identical).

- [ ] **Step 3: Commit any lint fixups**

```bash
git add -A && git commit -m "chore: lint fixups for mint_token interception (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Phase 2 — bounded use (jti-keyed Valkey counter)

### Task 9: `DecrementIfPositive` on the in-memory cache

**Files:**
- Modify: `internal/cache/cache.go` (interface)
- Modify: `internal/cache/memory.go`
- Test: `internal/cache/memory_test.go`

**Interfaces:**
- Produces: `Cache.DecrementIfPositive(ctx, key) (remaining int64, ok bool, err error)`.
  Semantics: missing key OR value ≤ 0 ⇒ `(-1, false, nil)`; otherwise decrement and return `(newValue, true, nil)` where `newValue ≥ 0`.

- [ ] **Step 1: Write the failing test**

Add to `internal/cache/memory_test.go`:

```go
func TestDecrementIfPositive_Memory(t *testing.T) {
	ttl := time.Minute
	mgr, _ := NewCacheManager("", "", &ttl)
	c := mgr.GetCache("cap", CacheOptions{Uncycled: true})
	ctx := context.Background()

	// missing key -> fail-closed
	rem, ok, err := c.DecrementIfPositive(ctx, "j1")
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, int64(-1), rem)

	assert.NoError(t, c.Set(ctx, "j1", "2"))
	rem, ok, _ = c.DecrementIfPositive(ctx, "j1")
	assert.True(t, ok)
	assert.Equal(t, int64(1), rem)
	rem, ok, _ = c.DecrementIfPositive(ctx, "j1")
	assert.True(t, ok)
	assert.Equal(t, int64(0), rem)
	rem, ok, _ = c.DecrementIfPositive(ctx, "j1") // exhausted
	assert.False(t, ok)
	assert.Equal(t, int64(-1), rem)
}

func TestDecrementIfPositive_Memory_Concurrent(t *testing.T) {
	ttl := time.Minute
	mgr, _ := NewCacheManager("", "", &ttl)
	c := mgr.GetCache("cap", CacheOptions{Uncycled: true})
	ctx := context.Background()
	_ = c.Set(ctx, "j", "100")
	var wg sync.WaitGroup
	var success int64
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, _ := c.DecrementIfPositive(ctx, "j"); ok {
				atomic.AddInt64(&success, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(100), success) // never over-spend
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/ -run TestDecrementIfPositive_Memory -v`
Expected: FAIL — `DecrementIfPositive` not in interface / not implemented.

- [ ] **Step 3a: Add to the interface**

In `internal/cache/cache.go`, add to the `Cache` interface:

```go
	// DecrementIfPositive atomically decrements the integer value at key when
	// it exists and is > 0, returning the remaining count and ok=true. When the
	// key is missing or already <= 0 it returns (-1, false, nil) WITHOUT
	// writing — the fail-closed primitive behind bounded-use capability tokens.
	DecrementIfPositive(ctx context.Context, key string) (remaining int64, ok bool, err error)
```

- [ ] **Step 3b: Implement in memory.go**

Add to `internal/cache/memory.go` (mirror the locking + prefix approach used by `Get`/`Set`; the in-memory cache stores string values, so parse/format the int). Implementation:

```go
func (c *InMemoryCache) DecrementIfPositive(ctx context.Context, key string) (int64, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, found := c.lookupLocked(key) // use whatever the existing Get path uses under lock
	if !found {
		return -1, false, nil
	}
	n, err := strconv.ParseInt(entry.value, 10, 64)
	if err != nil || n <= 0 {
		return -1, false, nil
	}
	n--
	entry.value = strconv.FormatInt(n, 10)
	c.storeLocked(key, entry) // preserve existing expiry
	return n, true, nil
}
```

Implementer note: `InMemoryCache` internals (field names, `mu`, entry struct, expiry handling) must be matched to the actual file — read `memory.go` `Get`/`Set` and reuse their exact map/lock/expiry mechanics rather than the illustrative `lookupLocked`/`storeLocked` names. The invariant: single critical section, do not reset TTL on decrement. Add `strconv` to imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cache/ -run TestDecrementIfPositive_Memory -v`
Expected: PASS (including the concurrency test under `-race`: `go test -race ./internal/cache/ -run TestDecrementIfPositive_Memory`).

- [ ] **Step 5: Commit**

```bash
git add internal/cache/cache.go internal/cache/memory.go internal/cache/memory_test.go
git commit -m "feat: cache DecrementIfPositive (in-memory) (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 10: `DecrementIfPositive` on the Valkey cache (Lua)

**Files:**
- Modify: `internal/cache/valkey.go`
- Test: `internal/cache/valkey_test.go`

**Interfaces:**
- Consumes: interface method from Task 9.
- Produces: Valkey implementation via a single atomic `EVAL`.

- [ ] **Step 1: Write the failing test**

Follow the existing `valkey_test.go` harness (it already stands up or skips against a Valkey/miniredis instance — mirror its setup/skip guard). Add:

```go
func TestDecrementIfPositive_Valkey(t *testing.T) {
	c := newTestValkeyCache(t) // mirror existing valkey_test setup; t.Skip if no server
	ctx := context.Background()

	rem, ok, err := c.DecrementIfPositive(ctx, "j1")
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, int64(-1), rem)

	assert.NoError(t, c.Set(ctx, "j1", "2"))
	rem, ok, _ = c.DecrementIfPositive(ctx, "j1")
	assert.True(t, ok)
	assert.Equal(t, int64(1), rem)
	rem, ok, _ = c.DecrementIfPositive(ctx, "j1")
	assert.True(t, ok)
	assert.Equal(t, int64(0), rem)
	rem, ok, _ = c.DecrementIfPositive(ctx, "j1")
	assert.False(t, ok)
	assert.Equal(t, int64(-1), rem)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/ -run TestDecrementIfPositive_Valkey -v`
Expected: FAIL — not implemented (or SKIP if no server; in that case rely on the memory test + a code review of the Lua, and run this in CI where Valkey is available).

- [ ] **Step 3: Implement with EVAL**

Add to `internal/cache/valkey.go`:

```go
// decrIfPositiveScript: fail-closed atomic decrement. Returns remaining (>=0)
// after a successful decrement, or -1 when the key is missing or already <= 0.
const decrIfPositiveScript = `
local v = redis.call('GET', KEYS[1])
if not v then return -1 end
local n = tonumber(v)
if not n or n <= 0 then return -1 end
redis.call('DECR', KEYS[1])
return n - 1`

func (s *ValkeyCache) DecrementIfPositive(ctx context.Context, key string) (int64, bool, error) {
	s.mu.RLock()
	prefix := s.prefix
	s.mu.RUnlock()

	cmd := s.client.B().Eval().Script(decrIfPositiveScript).Numkeys(1).Key(prefix + key).Build()
	rem, err := s.client.Do(ctx, cmd).ToInt64()
	if err != nil {
		return -1, false, err
	}
	if rem < 0 {
		return -1, false, nil
	}
	return rem, true, nil
}
```

(Confirm `ValkeyCache` uses `s.prefix` for keys the same way `Set` does; a bounded-use counter cache is created `Uncycled: true`, so `prevPrefix` fallback is not needed.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cache/ -run TestDecrementIfPositive_Valkey -v` (where a Valkey server is available).
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cache/valkey.go internal/cache/valkey_test.go
git commit -m "feat: cache DecrementIfPositive (valkey Lua) (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 11: Provision the counter at mint time

**Files:**
- Modify: `internal/host/mint_token.go` (`mintCapabilityToken` writes the counter)
- Modify: `internal/host/mint_token_test.go`

**Interfaces:**
- Consumes: `hh.cacheManager.GetCache("cap", cache.CacheOptions{Uncycled: true})`; `DecrementIfPositive` not used here (write only).
- Produces: after mint, a `cap:uses:<jti>` entry with TTL = token ttl and value = effective uses; `MintTokenResult.UsesRemaining` reflects the provisioned budget.

- [ ] **Step 1: Write the failing test**

Add to `internal/host/mint_token_test.go`:

```go
func TestMintCapabilityToken_ProvisionsCounter(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t), cacheManager: mgr}

	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"functions:/api/v1/files:write"},
		MintTokenRequest{Entitlements: []string{"functions:/api/v1/files:write"}, Uses: 3})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.UsesRemaining).To(Equal(3))

	// Extract jti and confirm the counter exists with value "3".
	var claims jwt.MapClaims
	_, _ = jwt.ParseWithClaims(res.Token, &claims, func(*jwt.Token) (any, error) {
		return hh.authConfig.ActivePair.Private.Public(), nil
	})
	jti := claims["jti"].(string)
	c := mgr.GetCache("cap", cache.CacheOptions{Uncycled: true})
	val, exists, _, _ := c.Get(context.Background(), "uses:"+jti)
	g.Expect(exists).To(BeTrue())
	g.Expect(val).To(Equal("3"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run TestMintCapabilityToken_ProvisionsCounter -v`
Expected: FAIL — no counter written.

- [ ] **Step 3: Write the counter at mint time**

In `mintCapabilityToken` (Task 4), after `token, err := signer.Sign(claims)` succeeds and before returning, add — but the jti is generated inside `SignProjected`, so re-parse the signed token to read its `jti` (unverified parse is fine; we just produced it), then provision:

```go
	// Provision the bounded-use counter keyed by the token's jti.
	if hh.cacheManager != nil {
		parsed, _, perr := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
		if perr == nil {
			if mc, ok := parsed.Claims.(jwt.MapClaims); ok {
				if jti, ok := mc["jti"].(string); ok && jti != "" {
					capCache := hh.cacheManager.GetCache("cap", cache.CacheOptions{Uncycled: true})
					_ = capCache.Set(ctx, "uses:"+jti, strconv.Itoa(uses), cache.WithTTL(ttl))
				}
			}
		}
	}
```

Add imports `strconv` and `github.com/kdex-tech/host-manager/internal/cache` to `mint_token.go`. (`jwt` already imported.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/host/ -run TestMintCapabilityToken -v`
Expected: PASS (the earlier stateless tests still pass — they use an `hh` with nil `cacheManager`, so provisioning is skipped).

- [ ] **Step 5: Commit**

```bash
git add internal/host/mint_token.go internal/host/mint_token_test.go
git commit -m "feat: provision jti-keyed use counter at mint time (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 12: Decrement the counter in inbound middleware (fail-closed)

**Files:**
- Modify: `internal/auth/middleware.go`
- Test: `internal/auth/middleware_capuses_test.go`

**Interfaces:**
- Consumes: the `capUsesClaim` marker (value `"kdx_cap"`) on a validated JWT; `Config`'s cache manager access — confirm how middleware reaches a `cache.Cache`. If `Config` does not already hold a `CacheManager`, thread one in: add `MintCapCache cache.Cache` to `Config`, set it in `Build` (`cfg.MintCapCache = cb.CacheManager.GetCache("cap", cache.CacheOptions{Uncycled:true})` when `MintTokenEnabled`), and use it here.
- Produces: requests bearing an exhausted/missing-counter capability token are rejected before reaching routing.

- [ ] **Step 1: Write the failing test**

Create `internal/auth/middleware_capuses_test.go`. Mint a capability JWT (uses=1) with the marker claim + a known `jti`, seed the `cap:uses:<jti>` counter in an in-memory cache to `1`, wrap a next-handler with `WithAuthentication`, and assert: first request passes (counter→0), second request is rejected (counter exhausted), and a request whose counter was never seeded is rejected (fail-closed). Use the same key material + config builder as the other middleware tests (`internal/auth/middleware_auto_extend_test.go` shows the harness).

```go
func TestWithAuthentication_BoundedUseDecrement(t *testing.T) {
	g := NewWithT(t)
	// ... build Config with MintTokenEnabled + an in-memory MintCapCache,
	// mint a marker JWT (uses=1) via the same signer, seed cap:uses:<jti>="1" ...
	// first call:
	//   rr1 := serve(reqWithBearer(token)); g.Expect(nextCalled).To(BeTrue())
	// second call (counter now 0):
	//   nextCalled=false; rr2 := serve(...); g.Expect(nextCalled).To(BeFalse())
	//   g.Expect(rr2.Code).To(Equal(http.StatusUnauthorized))
	// missing-counter token (different jti, never seeded): rejected.
}
```

Flesh out the harness by mirroring `middleware_auto_extend_test.go` (it already constructs a `Config`, signer, and drives `WithAuthentication`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestWithAuthentication_BoundedUseDecrement -v`
Expected: FAIL — no decrement path.

- [ ] **Step 3: Add the decrement after successful JWT validation**

In `internal/auth/middleware.go`, after the JWT is confirmed valid (the point where `token.Valid` is true and `authContext` is populated, i.e. AFTER the `if err != nil || !token.Valid` rejection block, before `next.ServeHTTP`), add:

```go
			// Bounded-use capability tokens carry the capUsesClaim marker and a
			// jti-keyed budget. Decrement atomically; reject (fail-closed) when
			// the counter is missing or exhausted. Ordinary tokens (no marker)
			// are untouched. See #280.
			if c.MintCapCache != nil {
				if marker, _ := authContext["kdx_cap"].(bool); marker {
					jti, _ := authContext["jti"].(string)
					if jti == "" {
						http.Error(w, "invalid capability token", http.StatusUnauthorized)
						return
					}
					if _, ok, derr := c.MintCapCache.DecrementIfPositive(r.Context(), "uses:"+jti); derr != nil || !ok {
						http.Error(w, "capability exhausted", http.StatusUnauthorized)
						return
					}
				}
			}
```

Notes:
- `authContext` is `AuthContext` (a `jwt.MapClaims`); `jti` is a standard registered claim and will be present as a string. Reference the marker by its literal `"kdx_cap"` or export `capUsesClaim` from the host package — simplest is to define the constant in the `auth` package (it owns the marker semantics) and have `internal/host/mint_token.go` reference `auth.CapUsesClaim`. Refactor: move `const capUsesClaim` to `auth` as exported `CapUsesClaim = "kdx_cap"` and update Task 4/7 references. Do this refactor as the first sub-step here so both packages share one source of truth.
- Add `MintCapCache cache.Cache` to `Config` and populate it in `ConfigBuilder.Build` under the `MintTokenEnabled` branch (requires `cb.CacheManager` — confirm the builder has one; the DCR store already uses `cb.CacheManager`, so it does).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run TestWithAuthentication_BoundedUseDecrement -v`
Then: `go test ./internal/auth/ ./internal/host/ -v`
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/middleware.go internal/auth/config.go internal/auth/middleware_capuses_test.go internal/host/mint_token.go internal/host/proxy.go
git commit -m "feat: enforce bounded-use via jti counter in middleware (fail-closed) (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 13: Final verification + sample manifest

**Files:**
- Create: `docs/superpowers/` note or a sample under the site repo is optional; the CRD sample lives with the consuming site (knowdrive-site `host.yaml`), NOT here — do not edit terraform/site manifests in this repo.

- [ ] **Step 1: Full module test + lint + race**

Run:
```bash
cd kdex-host-manager
make test
make lint
go test -race ./internal/cache/ ./internal/auth/ ./internal/host/
```
Expected: all PASS/clean.

- [ ] **Step 2: Manual smoke notes (document, do not execute here)**

Record in the PR description the manual verification to run against a dev cluster once deployed: enable `spec.auth.mintToken` on `rsi-dev`'s `KDexHost`, connect the MCP client, confirm `mint_token` appears in `tools/list`, mint `{entitlements:["functions:/api/v1/files:read"], uses:2}`, use the returned token twice against `GET /api/v1/files/{id}/content` (2nd is the last allowed), confirm the 3rd is 401, and confirm an over-broad request (`functions:/api/v1/files:*`) is rejected.

- [ ] **Step 3: Commit any final fixups**

```bash
git add -A && git commit -m "chore: mint_token final verification fixups (#280)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review (completed during authoring)

- **Spec coverage:** token shape → Task 4; interception (`tools/call` + `tools/list`) → Tasks 5–7; attenuation directional predicate → Task 1 (consumed Task 4); host-audience JWT trusted verbatim → relied on by Task 12 middleware + existing path (Task 7 e2e); opt-in `spec.auth.mintToken` → Tasks 2–3, gate Task 7; bounded-use jti counter + atomic decrement → Tasks 9–12; spend-on-attempt + fail-closed → Task 12; destructive-verb policy → Task 4 (`hasDestructiveVerb`) + config Task 3; documented per-VS held-set limitation → no code (behavioral; static held set is what `authContext["entitlements"]` carries on the connector path — Task 7 reads exactly that).
- **Placeholder scan:** all code steps contain concrete code; the two spots that must be adapted to real internals (in-memory cache internals in Task 9; middleware harness in Task 12) are called out explicitly with the invariant to preserve, not left as "TODO".
- **Type consistency:** `MintTokenRequest`/`MintTokenResult`/`mintCapabilityToken`/`capUsesClaim`(→ exported `auth.CapUsesClaim` in Task 12)/`DecrementIfPositive`/`mintTokenEnabled` used consistently across tasks; the Task-12 refactor of the marker constant is flagged where it happens.
