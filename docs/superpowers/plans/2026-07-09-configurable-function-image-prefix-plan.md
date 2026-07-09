# Configurable `FUNCTION_IMAGE_PREFIX` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a host-manager instance configure the function-image path prefix via a `FUNCTION_IMAGE_PREFIX` env var (default = host name, backward compatible), so knowdrive-site's `rsi-dev` and `rsi-prod` hosts share one function-image path (`…/kdex-docker/fn/<func>`) and promote to prod by adding a tag instead of copying images.

**Architecture:** host-manager builds each function image's destination as `{ImageRegistry}/{HostRef.Name}/{func}` in `internal/build/build.go`. This plan replaces the hardcoded `HostRef.Name` segment with a resolvable `Builder.ImagePrefix`, sourced from a new reconciler field, populated from `os.LookupEnv("FUNCTION_IMAGE_PREFIX")` in `cmd/main.go`. Unset → `HostRef.Name + "/"` (unchanged); set (incl. empty) → the literal value. The chart already passes `.Values.env` through, so no chart change. Then knowdrive-site adopts `fn/` on both hosts, rebuilds dev functions, and gains a `make promote` helper for tag-based prod promotion.

**Tech Stack:** Go (host-manager, controller-runtime, kpack Image unstructured), Helm (kdex-host-manager chart), Make + `docker buildx` + `gcloud artifacts` (knowdrive-site), Kubernetes/Knative/kpack, GCP Artifact Registry.

**Spec:** `docs/superpowers/specs/2026-07-09-configurable-function-image-prefix-design.md`

**Repos & branches:**
- `kdex-host-manager` — branch `feat/configurable-function-image-prefix` (Phase A). Path root below: repo root of kdex-host-manager.
- `knowdrive-site` (`/home/rotty/projects/RSI/knowdrive-site`, `main`) — Phase B. Paths prefixed `knowdrive-site/`.

## Global Constraints

- **Backward compatibility is non-negotiable:** with `FUNCTION_IMAGE_PREFIX` unset, every existing host-manager must build byte-identical image tags (`{registry}/{HostRef.Name}/{func}:latest` and `:{gen}`). No other site rebuilds or repins.
- **Tri-state via `os.LookupEnv`:** unset → host-name default; set-empty (`""`) → flat; set-value → literal. Use the `(value, ok)` tuple; a `*string` (nil = unset) carries it through structs.
- **The prefix string includes its own trailing slash** (`fn/`, `rsi-dev/`, or `""`). The tag format is `{registry}/{prefix}{func}:{tag}` (no separator between prefix and func).
- **Scope = function images only.** Do NOT touch `internal/packref` / the per-host `…/{host}/packages` image.
- **knowdrive-site value is `fn/`** (shared, non-empty — avoids `kdex-docker` root collisions).
- host-manager runs `make test` / `go test ./...`; follow existing test style (table tests, `package <pkg>` internal tests).

---

## Phase A — host-manager feature (branch `feat/configurable-function-image-prefix`)

### Task A1: Extract a pure image-ref helper + `Builder.ImagePrefix`, unit-tested

**Files:**
- Modify: `internal/build/build.go`
- Test: `internal/build/build_test.go` (create)

**Interfaces:**
- Produces: `Builder.ImagePrefix string`; unexported `imageRef(registry, prefix, name, tag string) string`. Consumed by Task A2 (sets `ImagePrefix`) and the two tag sites in `build.go`.

- [ ] **Step 1: Write the failing test** — `internal/build/build_test.go`:

```go
package build

import "testing"

func TestImageRef(t *testing.T) {
	const reg = "us-docker.pkg.dev/p/kdex-docker"
	cases := []struct {
		name, prefix, fn, tag, want string
	}{
		{"host-name prefix (default)", "rsi-dev/", "feedback", "latest", reg + "/rsi-dev/feedback:latest"},
		{"shared prefix", "fn/", "feedback", "7", reg + "/fn/feedback:7"},
		{"flat prefix", "", "feedback", "latest", reg + "/feedback:latest"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := imageRef(reg, c.prefix, c.fn, c.tag); got != c.want {
				t.Fatalf("imageRef = %q, want %q", got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run it — expect FAIL (undefined: imageRef)**

Run: `go test ./internal/build/ -run TestImageRef -v`
Expected: FAIL, `undefined: imageRef`.

- [ ] **Step 3: Implement** — in `internal/build/build.go`, add the field to `Builder` and the helper, and use it at the two tag sites.

Add to the `Builder` struct (after `ImageRegistry string`):
```go
	ImagePrefix    string // path segment before <func>, incl. trailing slash: "rsi-dev/", "fn/", or "" (flat)
```
Add the helper (package-level):
```go
// imageRef builds "<registry>/<prefix><name>:<tag>". prefix carries its own
// trailing slash (or is empty for a flat/root path).
func imageRef(registry, prefix, name, tag string) string {
	return fmt.Sprintf("%s/%s%s:%s", registry, prefix, name, tag)
}
```
Replace the `"tag"` / `"additionalTags"` lines (currently `build.go:52-55`):
```go
			"tag": imageRef(b.ImageRegistry, b.ImagePrefix, function.Name, "latest"),
			"additionalTags": []any{
				imageRef(b.ImageRegistry, b.ImagePrefix, function.Name, fmt.Sprintf("%d", function.GetGeneration())),
			},
```

- [ ] **Step 4: Run it — expect PASS**

Run: `go test ./internal/build/ -run TestImageRef -v`
Expected: PASS (all three sub-tests).

- [ ] **Step 5: Build the package**

Run: `go build ./internal/build/`
Expected: no output (success).

- [ ] **Step 6: Commit**

```bash
git add internal/build/build.go internal/build/build_test.go
git commit -m "feat(build): extract imageRef helper + Builder.ImagePrefix"
```

### Task A2: Resolve the prefix in the reconciler and pass it to the Builder

**Files:**
- Modify: `internal/controller/kdexfunction_controller.go`

**Interfaces:**
- Consumes: `Builder.ImagePrefix` (Task A1).
- Produces: `KDexFunctionReconciler.FunctionImagePrefix *string` (nil = unset). Consumed by Task A3 (main.go sets it).

- [ ] **Step 1: Add the field** to the `KDexFunctionReconciler` struct (`kdexfunction_controller.go:79`), after `FocalHost`:

```go
	// FunctionImagePrefix overrides the function-image path segment before
	// <func>. nil = unset (default to HostRef.Name+"/"); non-nil = literal
	// (may be "" for a flat path). From FUNCTION_IMAGE_PREFIX env in main.go.
	FunctionImagePrefix *string
```

- [ ] **Step 2: Resolve + set at the Builder site** (`kdexfunction_controller.go:~1167`). Immediately before `builder := build.Builder{`:

```go
		imagePrefix := hc.function.Spec.HostRef.Name + "/"
		if r.FunctionImagePrefix != nil {
			imagePrefix = *r.FunctionImagePrefix
		}
```
Then add `ImagePrefix: imagePrefix,` to the `build.Builder{…}` literal (next to `ImageRegistry:`).

- [ ] **Step 3: Build**

Run: `go build ./internal/controller/`
Expected: success.

- [ ] **Step 4: Verify existing controller tests still pass**

Run: `go test ./internal/controller/ 2>&1 | tail -5`
Expected: PASS (or the pre-existing pass/skip set — no new failures).

- [ ] **Step 5: Commit**

```bash
git add internal/controller/kdexfunction_controller.go
git commit -m "feat(controller): resolve function image prefix (default HostRef.Name)"
```

### Task A3: Read `FUNCTION_IMAGE_PREFIX` in main.go and wire it to the reconciler

**Files:**
- Modify: `cmd/main.go`

**Interfaces:**
- Consumes: `KDexFunctionReconciler.FunctionImagePrefix` (Task A2).

- [ ] **Step 1: Read the env** near the top of `main()` (with the other config reads, before the reconciler is constructed ~line 369):

```go
	var functionImagePrefix *string
	if v, ok := os.LookupEnv("FUNCTION_IMAGE_PREFIX"); ok {
		functionImagePrefix = &v
	}
```
(Confirm `os` is imported — it is, used by existing `os.Getenv` calls.)

- [ ] **Step 2: Pass it** into the `controller.KDexFunctionReconciler{…}` literal (`main.go:369`):

```go
		FunctionImagePrefix: functionImagePrefix,
```

- [ ] **Step 3: Build the whole binary**

Run: `go build ./...`
Expected: success.

- [ ] **Step 4: Full test suite**

Run: `go test ./... 2>&1 | tail -15`
Expected: no new failures vs baseline.

- [ ] **Step 5: Manual backward-compat check (unset) + override, via a tiny scratch test**

Add a temporary test proving resolution semantics, then delete it — OR rely on this reasoning check: `imageRef` is covered (A1); the nil-vs-set branch is 3 lines. Acceptable to verify by the dev-cluster behavior in Phase B (Task B3 checks both an overridden host and confirms the default path shape is documented). No extra unit test required beyond A1.

- [ ] **Step 6: Commit**

```bash
git add cmd/main.go
git commit -m "feat(main): read FUNCTION_IMAGE_PREFIX env into the function reconciler"
```

### Task A4: Release host-manager (image + chart) for knowdrive-site to consume

**Files:** none (release process per host-manager's conventions).

**Interfaces:**
- Produces: a published host-manager image + chart version that knowdrive-site's `rsi-dev` host can pin. Note the version for Phase B.

- [ ] **Step 1: Confirm no chart change is needed.** `grep -n 'Values.env' chart/templates/deployment.yaml` → the `{{- with .Values.env }}` block exists (renders arbitrary env). No edit. (If a future refactor removed it, re-add the 3-line block.)
- [ ] **Step 2: Tag/release** per host-manager's normal flow (bump chart `version`/`appVersion`, build+push the image, publish the chart). Record the resulting **version string** — Phase B pins it in `KDexHost.spec.helm.hostManager.chart.version` (or the nexus default).
- [ ] **Step 3: Merge `feat/configurable-function-image-prefix` → `main`** (PR or fast-forward per your policy). The feature is inert until an operator sets the env, so it's safe to ship ahead of adoption.

---

## Phase B — knowdrive-site adoption (repo `/home/rotty/projects/RSI/knowdrive-site`, `main`)

Prereq: Phase A released; note the host-manager version. Verify **dev first** (Tasks B1–B5); only then prod (B6).

### Task B1: Point credcheck's buildx path at `fn/`

**Files:**
- Modify: `knowdrive-site/Makefile`

- [ ] **Step 1:** Change `IMAGE_REPO` default (`Makefile:12`):
```make
IMAGE_REPO       ?= northamerica-northeast2-docker.pkg.dev/augeinnovations/kdex-docker/fn/user-credential-check
```
- [ ] **Step 2:** Update the stale comment block above it (drop the "Prod credcheck stays pinned in infra …" note at `Makefile:71-74`; the k8s/prod dir exists now and credcheck is promoted via `make promote`).
- [ ] **Step 3: Commit** (`git commit -m "chore(make): build credcheck to the shared fn/ image path"`). Do NOT build yet — build happens in B4 after the dev host is on the new prefix.

### Task B2: Set `FUNCTION_IMAGE_PREFIX=fn/` on the dev host + bump host-manager

**Files:**
- Modify: `knowdrive-site/k8s/dev/host.yaml`

- [ ] **Step 1:** In `spec.helm.hostManager.values`, add an `env` list (the chart passes it to the manager container):
```yaml
        env:
          - name: FUNCTION_IMAGE_PREFIX
            value: "fn/"
```
- [ ] **Step 2:** If the host pins `spec.helm.hostManager.chart.version`, bump it to the Phase-A release; else confirm the nexus default already points at it.
- [ ] **Step 3: Validate + apply**
```bash
make kubectl-validate-dev
make apply-dev
kubectl get pods -n dev -l app.kubernetes.io/name=kdex-host-manager -w   # wait new pod Ready (~60-90s)
```
- [ ] **Step 4: Verify the env landed**
```bash
kubectl get deploy rsi-dev -n dev -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="FUNCTION_IMAGE_PREFIX")].value}'
```
Expected: `fn/`.
- [ ] **Step 5: Commit** the host.yaml change.

### Task B3: Rebuild dev source-authoritative functions onto `fn/`; verify

**Files:** none (cluster ops).

- [ ] **Step 1:** For each source-authoritative function (`feedback`, `tenancy-service`, `user-service-auth`, `user-service-admin`, `user-service-profile`), trigger a rebuild by bumping generation (re-apply with a trivial `spec.env` nonce, or `kubectl annotate --overwrite` a spec change). The KDexFunction reconcile recreates the kpack `Image` with the new `fn/` tag.
- [ ] **Step 2: Verify the kpack Image destination moved**
```bash
kubectl get image.kpack.io -n dev -o custom-columns=NAME:.metadata.name,TAG:.spec.tag,READY:.status.conditions[0].status
```
Expected: `spec.tag` now `…/kdex-docker/fn/<func>:latest` for each; READY True after the build.
- [ ] **Step 3: Verify running image + Ready**
```bash
for fn in feedback tenancy-service user-service-auth user-service-admin user-service-profile; do
  echo "$fn -> $(kubectl get configuration $fn -n dev -o jsonpath='{.spec.template.spec.containers[0].image}')"
  kubectl get kdexfunction $fn -n dev -o jsonpath='{.metadata.name}: {.status.state}{"\n"}'
done
```
Expected: images under `…/kdex-docker/fn/…`; each `Ready`.
- [ ] **Step 4: Backward-compat spot check** — confirm a host WITHOUT the env is unaffected: pick another site's host-manager (or reason from A1's coverage) and confirm its kpack Images still target `…/{hostname}/<func>`. Document the check result.

### Task B4: Rebuild credcheck (executable) onto `fn/`; pin dev CR; verify

**Files:**
- Modify: `knowdrive-site/k8s/dev/function_user_credential_check.yaml`

- [ ] **Step 1: Build + push** to the new path:
```bash
cd knowdrive-site && make functions-credcheck
```
Expected: pushes `…/kdex-docker/fn/user-credential-check:0.1.0-<sha>` + `:latest`.
- [ ] **Step 2: Resolve the digest**
```bash
docker buildx imagetools inspect northamerica-northeast2-docker.pkg.dev/augeinnovations/kdex-docker/fn/user-credential-check:0.1.0-$(git rev-parse --short HEAD)
```
- [ ] **Step 3: Pin** the `image:` in `k8s/dev/function_user_credential_check.yaml` to `…/fn/user-credential-check:0.1.0-<sha>@sha256:<digest>`.
- [ ] **Step 4: Validate + apply + verify**
```bash
make kubectl-validate-dev && make apply-dev
kubectl get kdexfunction user-credential-check -n dev -o jsonpath='{.status.state}'   # Ready
kubectl get configuration user-credential-check -n dev -o jsonpath='{.spec.template.spec.containers[0].image}'  # …/fn/…
```
- [ ] **Step 5: Smoke** a login (credcheck path) against dev to confirm the new image works end-to-end (it reads the users DB; a successful auth exercises it).
- [ ] **Step 6: Commit** the dev CR pin.

### Task B5: `make promote` helper (tag-based promotion)

**Files:**
- Create: `knowdrive-site/scripts/promote.sh`
- Modify: `knowdrive-site/Makefile` (add `promote` target + `.PHONY`)

**Interfaces:**
- Produces: `make promote FUNC=<name>` → adds a `:prod` tag to a verified dev digest on the shared `fn/` path and prints the digest to pin.

- [ ] **Step 1: Write `scripts/promote.sh`** — resolves the function's current dev image digest and adds a `:prod` tag (same repo, no copy):
```bash
#!/usr/bin/env bash
# Promote a verified dev function image for prod use: add a :prod tag to the
# digest currently pinned in k8s/dev/function_<FUNC>.yaml (or running in dev),
# on the shared fn/ path. Prints the digest to pin in k8s/prod/.
set -euo pipefail
FUNC="${FUNC:?set FUNC=<function-name>, e.g. user-credential-check}"
REPO="northamerica-northeast2-docker.pkg.dev/augeinnovations/kdex-docker/fn/${FUNC}"
# Prefer the digest running in dev (authoritative "verified" artifact):
DIGEST="$(kubectl get configuration "${FUNC}" -n dev \
  -o jsonpath='{.spec.template.spec.containers[0].image}' | sed -n 's/.*@\(sha256:[0-9a-f]\+\).*/\1/p')"
[[ -n "$DIGEST" ]] || { echo "could not resolve dev digest for ${FUNC}" >&2; exit 1; }
echo "Promoting ${REPO}@${DIGEST} -> :prod"
gcloud artifacts docker tags add "${REPO}@${DIGEST}" "${REPO}:prod"
echo "Pin this in k8s/prod/function_${FUNC//-/_}.yaml (or the CR image line):"
echo "  ${REPO}:prod@${DIGEST}"
```
- [ ] **Step 2: Add the Makefile target**:
```make
promote:
	@FUNC="$(FUNC)" bash scripts/promote.sh
```
and add `promote` to the `.PHONY` line.
- [ ] **Step 3: Dry-run test** (no cluster mutation): run with a non-existent FUNC to confirm the guard fires:
```bash
FUNC= make promote 2>&1 | head -1   # expect the ":?" guard error
```
Expected: errors asking for FUNC. (Real promotion is exercised in B6.)
- [ ] **Step 4: Commit** the script + Makefile target.

### Task B6: Prod — enable `fn/`, promote + pin credcheck, verify

**Files:**
- Modify: `knowdrive-site/k8s/prod/host.yaml`, `knowdrive-site/k8s/prod/function_user_credential_check.yaml`

- [ ] **Step 1:** Add the same `env: [{name: FUNCTION_IMAGE_PREFIX, value: "fn/"}]` to `k8s/prod/host.yaml` `spec.helm.hostManager.values`; bump the host-manager version to the Phase-A release. Validate + apply; wait for rollover; confirm the env landed (mirror B2 Step 4 with `-n prod`).
- [ ] **Step 2: Promote credcheck**:
```bash
cd knowdrive-site && FUNC=user-credential-check make promote
```
Expected: `:prod` tag added to dev's verified `fn/user-credential-check` digest; prints the `…/fn/…:prod@sha256:<d>` ref.
- [ ] **Step 3: Pin** that ref in `k8s/prod/function_user_credential_check.yaml` `image:`.
- [ ] **Step 4: Validate + apply + verify**
```bash
make kubectl-validate-prod && make apply-prod
kubectl get kdexfunction user-credential-check -n prod -o jsonpath='{.status.state}'   # Ready
kubectl get configuration user-credential-check -n prod -o jsonpath='{.spec.template.spec.containers[0].image}'  # …/fn/…:prod@sha256:…
```
Expected: prod credcheck now runs the **same digest** as verified in dev, on the shared `fn/` path.
- [ ] **Step 5: Smoke** a prod login to confirm credcheck works against `rsi-users-prod`.
- [ ] **Step 6: Commit** the prod host.yaml + CR pin.

---

## Self-Review

**Spec coverage:** Every spec element maps to a task — `build.go` prefix + helper (A1), reconciler resolution with host-name default (A2), env read (A3), release/backward-compat (A4/B3-Step4), chart "no change" confirmed (A4-Step1), knowdrive Makefile (B1), host env on dev+prod (B2/B6), rebuild source-auth (B3) + executable credcheck (B4), tag-based `make promote` (B5), credcheck prod alignment via promotion (B6). Packages image is explicitly untouched (Global Constraints + no task references `packref`).

**Placeholder scan:** No TBD/TODO. Code steps show full code; command steps show exact commands + expected output. `<sha>`/`<digest>` are genuine build/inspect outputs resolved at run time (B4 Steps 1-3), not unfilled blanks. A4's release step defers to "host-manager's normal flow" — the one legitimately repo/maintainer-specific step; its output (a version string) is named and consumed in B2/B6.

**Type consistency:** `Builder.ImagePrefix string` (A1) ↔ set in A2's `build.Builder{…}` literal. `KDexFunctionReconciler.FunctionImagePrefix *string` (A2) ↔ set in A3's `main.go` literal. `imageRef(registry, prefix, name, tag string)` signature identical across A1's test, helper, and the two call sites.

**Ambiguity:** The unset/empty/value tri-state is pinned to `os.LookupEnv`'s `(value, ok)` → `*string` (nil=unset). Prefix-carries-slash is stated in Global Constraints and every format string matches (`%s/%s%s`).
