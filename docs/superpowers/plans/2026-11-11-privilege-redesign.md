# Privilege Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the namespace the unit of security for KDex: host-manager holds namespaced RBAC only, Helm installs run as a per-namespace installer, host-manager's token never reaches foreign pods, cross-namespace references are refused, companions are OCI-only.

**Architecture:** host-manager's chart ships its own namespaced Roles (generated from its kubebuilder markers) plus a function-deployer SA. nexus bootstraps a `kdex-installer` SA per host namespace, impersonates it for every Helm action, maintains one fixed cluster-reader ClusterRoleBinding, and removes the legacy per-host ClusterRole/ClusterRoleBinding make-before-break. Release A (this plan) migrates; release B (follow-up, last task files it) deletes the migration code and trims nexus's role.

**Tech Stack:** Go 1.26.0, controller-runtime, controller-gen v0.20.1, Helm Go SDK v4.1.3, Ginkgo/envtest, helm CLI (`bin/helm`), yq.

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-11-11-privilege-redesign-design.md` (d57235f)

## Global Constraints

- No kdex-crds change. No `./updateCrdUsage.sh` run. If a task finds a schema change unavoidable, stop and ask.
- Go 1.26.0; Go lint needs `GOTOOLCHAIN=go1.26.0`.
- Fixed names (exact):
  - installer SA: `kdex-installer` (same string in nexus and host-manager; each declares a constant with a comment naming the other repo's).
  - nexus ClusterRoles: `kcnas-operator-installer` (aggregated, `aggregationRule` on label `kdex.dev/aggregate-to-installer: "true"`), `kcnas-operator-installer-base` (carries that label), `kcnas-operator-host-manager-cluster-reader`; ClusterRoleBinding `kcnas-operator-host-manager-cluster-reader`.
  - host-manager chart: Role + RoleBinding `<fullname>`; SA + Role + RoleBinding `<fullname>-function-deployer`.
  - ownership label on everything nexus creates outside Helm: `app.kubernetes.io/managed-by: kcnas-operator`.
  - installer RoleBinding finalizer: `kdex.dev/installer`.
  - host conditions/reasons: `ReferenceNamespacesDisabled`, `LegacyRBACPresent`, `HostManagerChartUnsupported`, `CompanionChartRefused`.
- Minimum host-manager chart version: `0.33.0` (the host-manager release this plan produces; adjust the constant if the tag differs).
- Commits are signed (`git commit -S` is the repo default); commit inside the sub-repo; end messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- After code changes run `make lint` from the workspace root.
- Run each repo's `make test` before its release task. Parallel `make test` across repos collides on :8080 — run them sequentially.

## Review Focus

1. **A host never upgraded under the new nexus is deleted** (legacy ClusterRole still in its Helm record) — teardown must complete, not wedge on Forbidden. Test in Task N7.
2. **Two KDexHosts share a namespace; one is deleted** — the installer SA/RoleBinding must survive for the other. Test in Task N6.
3. **Same-named hosts in two namespaces during migration** — cleanup for one must never delete the other's legacy ClusterRole. Test in Task N7.
4. **Host values set `serviceAccount.create: false` / `serviceAccount.name`** — the cluster-reader subject must name the SA the chart actually renders. Test in Task N5.
5. **Backend Deployment template names host-manager's SA** (via `config.backendDefault.deployment`) — refused, never deployed with its token. Test in Task H3.

---

## Part H — kdex-host-manager

### Task H1: Namespaced, generated host-manager RBAC in the chart

**Files:**
- Modify: `internal/controller/rbac.go` (all markers)
- Modify: `Makefile` (`manifests` target; new `chart-rbac` target)
- Create: `hack/chart-role-header.yaml` (template header for the generated Role)
- Create: `chart/templates/role.yaml` (generated), `chart/templates/rolebinding.yaml`
- Delete: `chart/templates/clusterrole.yaml`, `chart/templates/clusterrolebinding.yaml`
- Modify: `chart/values.yaml` (delete `roleRef`)
- Modify: `.github/workflows/ci.yml` (drift check)
- Test: `chart/render_test.go`

**Interfaces:**
- Produces: chart renders `Role/<fullname>` + `RoleBinding/<fullname>` (subject = `host-manager.serviceAccountName`), and no cluster-scoped RBAC. `make chart-rbac` regenerates `chart/templates/role.yaml` from `config/rbac/role.yaml`.

- [ ] **Step 1: Write the failing render tests** in `chart/render_test.go`:
  - `TestRender_NoClusterScopedRBAC`: render with defaults; assert output contains no `kind: ClusterRole` and no `kind: ClusterRoleBinding`.
  - `TestRender_RoleBindingNamesChartServiceAccount`: render with `--set serviceAccount.name=custom`; assert a `kind: RoleBinding` whose `roleRef.kind: Role`, `roleRef.name: <fullname>` and subject `name: custom`.
  - `TestRender_RoleOmitsClusterKinds`: assert the rendered `Role` mentions no resource starting with `kdexcluster`.
- [ ] **Step 2: Run** `go test ./chart/ -run 'TestRender_(NoClusterScopedRBAC|RoleBindingNamesChartServiceAccount|RoleOmitsClusterKinds)' -v` — Expected: FAIL (ClusterRole rendered).
- [ ] **Step 3: Rewrite the markers in `internal/controller/rbac.go`.** Namespaced rules get `namespace=host-namespace` (a placeholder; controller-gen then emits a `Role` in `config/rbac/role.yaml`); the `kdexcluster*` get/list/watch markers keep no namespace (emitted as the `ClusterRole`, consumed only by local `make run`; nexus's cluster-reader covers them in prod). Apply the grant corrections from the spec (§D1 "Grant corrections"): drop persistentvolumeclaims, gateways, serving.knative.dev, kpack `images/finalizers` and `images/status`, and the listed unused verbs. Keep `/finalizers` update on kdexfunctions, kdexinternalhosts, kdexinternalpackagereferences with the comment `// Needed for blockOwnerDeletion when OwnerReferencesPermissionEnforcement is enabled.` Before trimming each verb, `rg` its call sites; if a verb is used that the spec lists as unused, keep it and note it in the commit message.
- [ ] **Step 4: Add `chart-rbac` to the Makefile** and call it at the end of `manifests`: `yq` selects the `kind == "Role"` document's `rules` from `config/rbac/role.yaml` and writes `hack/chart-role-header.yaml` (apiVersion/kind/metadata with `{{ include "host-manager.fullname" . }}`, `{{ .Release.Namespace }}`, labels) followed by `rules:` into `chart/templates/role.yaml`, prefixed with `# GENERATED by make chart-rbac from internal/controller/rbac.go — do not edit.`
- [ ] **Step 5: Write `chart/templates/rolebinding.yaml`** binding `Role/<fullname>` to `host-manager.serviceAccountName` in `.Release.Namespace`. Delete the two cluster templates and `roleRef` from `values.yaml`.
- [ ] **Step 6: Add a CI step** after `make test` in `ci.yml`: `git diff --exit-code config/rbac chart/templates/role.yaml`.
- [ ] **Step 7: Run** `make manifests && go test ./chart/ -v && make lint-chart` — Expected: PASS; `git diff config/rbac` shows the Role document.
- [ ] **Step 8: Commit** `feat(rbac): ship namespaced, generated RBAC in the chart`.

### Task H2: Function-deployer ServiceAccount for deployer and observer

**Files:**
- Create: `chart/templates/function-deployer-serviceaccount.yaml`, `chart/templates/function-deployer-role.yaml`, `chart/templates/function-deployer-rolebinding.yaml` (one resource per file, workspace rule)
- Modify: `chart/templates/deployment.yaml` (env `FUNCTION_DEPLOYER_SERVICE_ACCOUNT`)
- Modify: `internal/controller/kdexfunction_controller.go:112,271,1612` (handler context + `deployer()`)
- Test: `chart/render_test.go`, `internal/controller/kdexfunction_deployer_sa_test.go`

**Interfaces:**
- Produces: env var `FUNCTION_DEPLOYER_SERVICE_ACCOUNT` = `<fullname>-function-deployer`; `handlerContext.deployerServiceAccount string`; `deploy.Deployer.ServiceAccount` now carries the deployer SA.

- [ ] **Step 1: Failing tests.**
  - `TestRender_FunctionDeployerRBAC`: rendered `Role/<fullname>-function-deployer` has exactly these rules: `serving.knative.dev services [get, patch]`, `kdex.dev kdexfunctions [get, list]`, `kdex.dev kdexfunctions/status [patch]`, `kpack.io images [get, patch]`, `kpack.io builds [get]`, `"" pods [get]`; a `RoleBinding` to it for SA `<fullname>-function-deployer`; and the Deployment env has `FUNCTION_DEPLOYER_SERVICE_ACCOUNT=<fullname>-function-deployer`.
  - `TestDeployer_UsesFunctionDeployerServiceAccount`: build a reconciler whose handler context has `serviceAccount: "rsi-dev"`, `deployerServiceAccount: "rsi-dev-function-deployer"`; assert `r.deployer(hc).ServiceAccount == "rsi-dev-function-deployer"`.
- [ ] **Step 2: Run** `go test ./chart/ ./internal/controller/ -run 'FunctionDeployer|UsesFunctionDeployer' -v` — Expected: FAIL.
- [ ] **Step 3: Implement.** Chart files with a comment per rule citing the kdex-knative-deployer call (`cmd/main.go:420,762` SSA+get services; `main.go:472,480,708` kdexfunctions; `retry.go:105,347` images; `retry.go:126` builds; `retry.go:208` pods). In the controller read `FUNCTION_DEPLOYER_SERVICE_ACCOUNT` next to `KUBERNETES_SERVICE_ACCOUNT` (line 271) into `deployerServiceAccount`; `deployer()` uses it. If empty (old chart), mark the function Degraded with `"FUNCTION_DEPLOYER_SERVICE_ACCOUNT is not set; upgrade the host-manager chart"` and do not deploy.
- [ ] **Step 4: SSA create check.** Run the deployer against envtest or a kind cluster once with only the Role above; if the first apply of a new Knative Service is Forbidden for `create`, add `create` to the services rule and to the test.
- [ ] **Step 5: Run** the Step 2 command — Expected: PASS.
- [ ] **Step 6: Commit** `feat(deploy): run deployer and observer as a dedicated ServiceAccount`.

### Task H3: Reserved ServiceAccounts, no build fallback, backend token off

**Files:**
- Modify: `internal/controller/kdexfunction_controller.go:1420-1436,1557-1594,1637-1641`
- Modify: `internal/controller/kdexinternalhost_controller.go` (backend Deployment mutate fn near 1660-1720; delete dead SA watch at 976-978)
- Create: `internal/controller/reserved_service_accounts.go`
- Test: `internal/controller/reference_namespaces_test.go:149` (update), `internal/controller/reserved_service_accounts_test.go`, `internal/controller/kdexinternalhost_backend_deployment_test.go`

**Interfaces:**
- Consumes: `handlerContext.deployerServiceAccount` (H2).
- Produces: `const InstallerServiceAccountName = "kdex-installer"` (comment: must equal nexus `internal/controller` constant of the same name); `func reservedServiceAccount(sa, hostManagerSA, deployerSA string, account *corev1.ServiceAccount) bool`; `func (r *KDexFunctionReconciler) refuseReservedServiceAccount(hc handlerContext, field, sa string) error` replacing `refuseHostManagerServiceAccount`.

- [ ] **Step 1: Failing tests.**
  - `TestReservedServiceAccount`: table — `kdex-installer` → true; equal to hostManagerSA → true; equal to deployerSA → true; account labelled `app.kubernetes.io/name: host-manager` → true; `kdex-builder` unlabelled → false; `default` → false.
  - `TestBuild_EmptyServiceAccountRefused`: function with source origin, adaptor builder with no SA, no inline SA → function Degraded with message containing `no build ServiceAccount`; no kpack Image created.
  - `TestBackendDeployment_TokenNotMounted`: reconcile a backend Deployment; assert `Spec.Template.Spec.AutomountServiceAccountToken` is `false`.
  - `TestBackendDeployment_ReservedServiceAccountRefused`: configuration `BackendDefault.Deployment.Spec.Template.Spec.ServiceAccountName = <host-manager SA>` → no Deployment created, KDexInternalHost Degraded with message naming the field.
  - `TestFaaSAdaptor_OtherNamespaceRefused`: `faasAdaptorRef` with `namespace: other`, empty referenceNamespaces → host Degraded via `checkReferenceNamespace`; no Job created. (Pins existing behavior the spec relies on.)
- [ ] **Step 2: Run** `go test ./internal/controller/ -run 'Reserved|EmptyServiceAccount|TokenNotMounted|OtherNamespaceRefused' -v` — Expected: FAIL (except the FaaSAdaptor test, which may already pass; keep it).
- [ ] **Step 3: Implement.** `reservedServiceAccount` in the new file (fold `isHostManagerServiceAccount` into it). `refuseReservedServiceAccount` keeps today's Degraded condition shape, message `"%s %q is a reserved ServiceAccount (host-manager, function-deployer or kdex-installer); a function must run as its own"`. Build path: `buildSA` starts empty; empty after resolution → Degraded `"no build ServiceAccount: set spec.origin.source.builder.serviceAccountName or the FaaSAdaptor builder's serviceAccountName"` and return. Delete the "known gap" comment. Backend Deployment: force `AutomountServiceAccountToken = ptr.To(false)`; before `CreateOrUpdate`, if the template SA is reserved, set the condition and skip. Delete the `ServiceAccount` watch at 976-978.
- [ ] **Step 4: Run** the Step 2 command, then `go test ./internal/controller/ -run 'ReferenceNamespace' -v` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(security): reserved ServiceAccounts, no build fallback, no backend token`.

---

## Part K — kdex-knative-deployer

### Task K1: Drop the nodes lookup and the deployer chart's own RBAC

**Files:**
- Modify: `cmd/retry.go` (delete signal 3, `isNodeNotReady`, `nodeGVR`)
- Modify: `cmd/retry_test.go` (delete `TestIsBuildPodPreempted_NodeNotReady`, `TestIsBuildPodPreempted_NodeGone`, `newNode`, the `nodeGVR` list registration)
- Modify: `chart/templates/faas-adaptor.yaml:12,25` (remove `serviceAccountName` lines)
- Delete: `chart/templates/rbac.yaml` and, if nothing else references it, `chart/templates/serviceaccount.yaml` + `rbac`/`serviceAccount` values
- Modify: `verify-addon.sh` if it asserts on the removed objects

- [ ] **Step 1:** `rg -n "serviceAccountName|kdex-knative-faas-adaptor.serviceAccountName" chart/` — confirm only `faas-adaptor.yaml`, `rbac.yaml`, `serviceaccount.yaml`, `_helpers.tpl` use it. If the knative/kpack subtemplates use the SA, keep `serviceaccount.yaml` and say so in the commit.
- [ ] **Step 2: Failing test** `TestIsBuildPodPreempted_NoNodeLookup`: fake dynamic client with **no** Node registered and a pod whose `spec.nodeName` is set and has no preemption reason → `isBuildPodPreempted` returns `false, nil` (today it errors on the node GET).
- [ ] **Step 3: Run** `go test ./cmd/ -run NoNodeLookup -v` — Expected: FAIL.
- [ ] **Step 4: Implement** the deletions listed under Files. Keep signals 1, 2 and the init-container Killed check.
- [ ] **Step 5: Run** `make test && make lint` — Expected: PASS (`verify-chart` included).
- [ ] **Step 6: Commit** `refactor: remove node lookup and unused chart RBAC (privilege redesign)`.

---

## Part N — kdex-nexus-manager

### Task N1: Fixed roles in config/rbac, single source, drift check

**Files:**
- Create: `config/rbac/installer_role.yaml` (aggregated `kcnas-operator-installer`, rules `[]`), `config/rbac/installer_base_role.yaml`, `config/rbac/cluster_reader_role.yaml`, `config/rbac/cluster_reader_role_binding.yaml` (subjects `[]`)
- Modify: `config/rbac/kustomization.yaml`
- Delete: `config/rbac/host-controller-role.yaml`, `chart/templates/rbac/host-controller-role.yaml`
- Modify: `chart/templates/manager/manager.yaml:67-80` (drop the `HOST_MANAGER_CLUSTER_ROLE` entry; render `env:` when `env` **or** `extraEnv` is set)
- Modify: `internal/controller/rbac.go` (add nexus's new grants)
- Regenerate: `chart/templates/rbac/*` via `make update-chart`
- Test: `internal/controller/rbac_manifests_test.go`

**Interfaces:**
- Produces: the fixed names in Global Constraints, present in both kustomize and chart.

- [ ] **Step 1: Failing tests** in `rbac_manifests_test.go` (plain `testing`, reads files relative to repo root):
  - `TestChartRBACMatchesConfig`: for every `config/rbac/*.yaml` with kind Role/ClusterRole/RoleBinding/ClusterRoleBinding, the chart file of the same kind+base name exists and its `rules` / `aggregationRule` / `roleRef` are equal after stripping lines containing `{{`.
  - `TestClusterReaderCoversClusterScopedKDexKinds`: list `config/crd/bases/*.yaml` in the kdex-crds module dir (`go list -m -f '{{.Dir}}' kdex.dev/crds`); every CRD with `scope: Cluster` whose kind starts `KDexCluster` has its plural in the cluster-reader rules with verbs exactly `[get, list, watch]`.
  - `TestInstallerBaseCoversLiveCompanions`: installer-base rules include create/update/patch/delete/get/list/watch on: configmaps, services, serviceaccounts, persistentvolumeclaims, secrets (core); deployments (apps); kdexapps, kdexfunctions, kdexhostextensions, kdexpages, kdexroles, kdexrolebindings, kdextranslations (kdex.dev); roles and rolebindings (rbac) plus `escalate` and `bind` on roles.
  - `TestNoHostManagerClusterRoleEnv`: `chart/templates/manager/manager.yaml` does not contain `HOST_MANAGER_CLUSTER_ROLE`.
- [ ] **Step 2: Run** `go test ./internal/controller/ -run 'ChartRBAC|ClusterReader|InstallerBase|NoHostManagerClusterRoleEnv' -v` — Expected: FAIL.
- [ ] **Step 3: Write the YAML.** Installer-base: the kinds from the test, plus every namespaced kdex.dev authoring kind (for symmetry), labelled `kdex.dev/aggregate-to-installer: "true"`. Add markers to `internal/controller/rbac.go`: `impersonate` on serviceaccounts `resourceNames=kdex-installer`; get/list/watch/create/update/delete on serviceaccounts and rolebindings (rbac.authorization.k8s.io); `bind` on clusterroles `resourceNames=kcnas-operator-installer`; get/update/patch on clusterrolebindings `resourceNames=kcnas-operator-host-manager-cluster-reader`; `get` on namespaces. **Do not remove any existing nexus grant in this release** (Review Focus 1 needs them for legacy uninstall; Task N9 files the trim).
- [ ] **Step 4: Run** `make manifests update-chart` and inspect `git diff chart/`: if `update-chart` rewrites unrelated chart files, revert those hunks and note in the commit that the helm plugin is not idempotent (the drift test still guards RBAC).
- [ ] **Step 5: Run** the Step 2 command — Expected: PASS. Then `make lint-chart`.
- [ ] **Step 6: Commit** `feat(rbac): fixed installer and cluster-reader roles, single source`.

### Task N2: Impersonating Helm clients

**Files:**
- Modify: `internal/utils/helm.go:113-183` (`HelmClient`, `NewHelmClient`, new option)
- Modify: `internal/controller/kdexhost_controller.go:104,899-956` (factory signature, cache key)
- Modify: `cmd/main.go:300`
- Test: `internal/utils/helm_impersonation_test.go`, `internal/controller/helm_client_cache_test.go`

**Interfaces:**
- Produces:
  - `func WithImpersonation(user string) HelmClientOption` — sets `settings.KubeAsUser` **before** `actionConfig.Init`.
  - `func InstallerUser(namespace string) string` → `"system:serviceaccount:<ns>:kdex-installer"`.
  - `type HelmIdentity int` with `HelmAsInstaller`, `HelmAsOperator`.
  - `HelmClientFactory func(namespace string, secrets kdexv1alpha1.Secrets, logger logr.Logger, identity HelmIdentity) (utils.HelmClientInterface, error)`.
  - `getOrCreateHelmClient(name, namespace string, secrets kdexv1alpha1.Secrets, logger logr.Logger, identity HelmIdentity)`; cache key includes the identity; `deleteHelmClient` drops both.

- [ ] **Step 1: Failing tests.**
  - `TestNewHelmClient_ImpersonationSetBeforeInit`: `NewHelmClient("ns", nil, logr.Discard(), WithImpersonation(InstallerUser("ns")))`; assert `h.settings.KubeAsUser == "system:serviceaccount:ns:kdex-installer"` and that `h.settings.RESTClientGetter().ToRESTConfig()` has `Impersonate.UserName` equal to it (needs a kubeconfig; use `t.Setenv("KUBECONFIG", <temp kubeconfig pointing at 127.0.0.1>)`).
  - `TestHelmClientCache_SeparatePerIdentity` (extend `helm_client_cache_test.go`): two calls with the same host and different identities return different clients; the factory saw both identities.
- [ ] **Step 2: Run** `go test ./internal/utils/ ./internal/controller/ -run 'Impersonation|SeparatePerIdentity' -v` — Expected: FAIL.
- [ ] **Step 3: Implement.** In `NewHelmClient`, apply options that touch `settings` before `actionConfig.Init` (split options into pre-init and post-init, or apply all before Init — the existing `WithRegistryFetchMaxBytes` only sets a field). Update every factory caller and test stub to the new signature.
- [ ] **Step 4: Run** the Step 2 command and `go build ./...` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(helm): impersonating Helm clients per identity`.

### Task N3: Companions — OCI only, bounded, metadata-only listing (#61-#64)

**Files:**
- Modify: `internal/controller/kdexhost_controller_helm.go:992-1010` (drop `AddRepository`), `:605-675` (call the check before step 1)
- Modify: `internal/utils/helm.go:105-111,185-213,264-290` (remove `AddRepository`; rewrite `ListReleases`)
- Modify: `cmd/main.go` (flags `--chart-max-decompressed-bytes`, `--chart-max-file-bytes`; set Helm's `archive.MaxDecompressedChartSize` / `MaxDecompressedFileSize` at startup)
- Test: `internal/controller/companion_sources_test.go`, `internal/utils/helm_list_releases_test.go`

**Interfaces:**
- Produces: `func checkCompanionSources(host *kdexv1alpha1.KDexHost) error`; `func WithMetadataReader(r client.Reader) HelmClientOption`; `ListReleases` keeps its signature and returns the `name` label values of Secrets in the client's namespace labelled `owner=helm` + `matchLabels`, read as `metav1.PartialObjectMetadataList`.

- [ ] **Step 1: Failing tests.**
  - `TestCheckCompanionSources`: table — `oci://registry.gitlab.com/x/charts/y` → nil; `/var/cache/helm/x.tgz`, `file:///x`, `https://h/x.tgz`, `repo/chart` → error mentioning `oci://`; any chart with `Repository: "https://h"` → error mentioning `repository`.
  - `TestHelmRun_RefusedCompanionInstallsNothing`: fake Helm client; host with one `file://` companion → no `InstallOrUpgrade` call at all (host-manager chart included), host condition reason `CompanionChartRefused`.
  - `TestListReleases_MetadataOnly`: fake client with Secrets (labels `owner=helm,name=a,kdex.dev/companion-of=h`), (`owner=helm,name=b`), (`owner=helm,name=a,...` second revision) → `ListReleases({"kdex.dev/companion-of":"h"})` returns `["a"]`.
  - `TestChartSizeFlagsApplied`: after flag parsing helper `applyChartSizeLimits(16<<20, 4<<20)`, `archive.MaxDecompressedChartSize == 16<<20` and `MaxDecompressedFileSize == 4<<20`.
- [ ] **Step 2: Run** `go test ./internal/... ./cmd/... -run 'CompanionSources|RefusedCompanion|MetadataOnly|ChartSizeFlags' -v` — Expected: FAIL.
- [ ] **Step 3: Implement.** Defaults: chart 16 MiB, file 4 MiB; the flag help states the budget rule (cap × render overhead × concurrent renders must fit the memory limit) the way `RegistryFetchMaxBytes` documents its own. Wire `WithMetadataReader(mgr.GetAPIReader())` in the factory.
- [ ] **Step 4: Run** the Step 2 command — Expected: PASS.
- [ ] **Step 5: Commit** `feat(companions): OCI only, bounded chart size, metadata-only release listing (#61 #62 #63 #64)`.

### Task N4: Cross-namespace references refused

**Files:**
- Modify: `internal/controller/resolver_common.go:218-288,324-380`
- Modify: `internal/controller/kdexapp_controller.go:121-130`, `internal/controller/kdexscriptlibrary_controller.go:121-130`
- Modify: `internal/controller/kdexhost_controller_helm.go:956-967` (referenceNamespaces → empty + condition)
- Test: `internal/controller/cross_namespace_refusal_test.go`

**Interfaces:**
- Produces: `var errCrossNamespaceReference` with the uniform message `"references to other namespaces are disabled"`; `func ResolveOperatorSecret(ctx context.Context, c client.Client, object client.Object, conds *[]metav1.Condition, ref *kdexv1alpha1.KDexObjectReference, requeueDelay time.Duration) (*corev1.Secret, bool, ctrl.Result, error)` (no namespace rule — for NexusConfiguration refs only).

- [ ] **Step 1: Failing tests.**
  - `TestResolveKDexObjectReference_OtherNamespaceRefusedBeforeGet`: referrer in `a`, ref `{Kind: KDexTheme, Name: t, Namespace: b}`; client wrapper counts Gets → returns error `errCrossNamespaceReference`, condition message equal for an existing and a missing target, zero Gets.
  - `TestResolveSecret_OtherNamespaceRefused`: same shape for a `KDexObjectReference` secretRef.
  - `TestResolveOperatorSecret_AllowsConfiguredNamespace`: secret in `kcnas-system`, referrer in `a` → resolved.
  - `TestHostManagerValues_ReferenceNamespacesDisabled`: host with `ReferenceNamespaces: ["b"]` → built values `referenceNamespaces == []` and host condition `ReferenceNamespacesDisabled` true.
- [ ] **Step 2: Run** `go test ./internal/controller/ -run 'OtherNamespace|OperatorSecret|ReferenceNamespacesDisabled' -v` — Expected: FAIL.
- [ ] **Step 3: Implement.** Check the namespace before `Get`; same-namespace and empty namespace still allowed; cluster-scoped rules unchanged. App and script-library controllers call `ResolveOperatorSecret` when they fall back to `r.Configuration.DefaultNpmSecretRef`.
- [ ] **Step 4: Run** the Step 2 command, then the full `go test ./internal/controller/` (envtest) — Expected: PASS.
- [ ] **Step 5: Commit** `feat(security): refuse cross-namespace references`.

### Task N5: Host-manager chart spec — min version, no roleRef, cluster-reader subject

**Files:**
- Modify: `internal/controller/kdexhost_controller_helm.go:900-990`
- Create: `internal/controller/cluster_reader.go`
- Test: `internal/controller/host_manager_chart_spec_test.go`, `internal/controller/cluster_reader_test.go`

**Interfaces:**
- Consumes: N1 names.
- Produces:
  - `const MinHostManagerChartVersion = "0.33.0"`; `func checkHostManagerChartVersion(version string) error` (strict semver ≥ min, else error).
  - `func hostManagerServiceAccountName(vals map[string]any, hostName string) string` — mirrors `host-manager.serviceAccountName` in `kdex-host-manager/chart/templates/_helpers.tpl:62-68`.
  - `func (r *KDexHostReconciler) ensureClusterReaderSubject(ctx context.Context, namespace, sa string) error` / `removeClusterReaderSubject(...)` — read-modify-update of the fixed ClusterRoleBinding with optimistic-lock retry; idempotent.

- [ ] **Step 1: Failing tests.**
  - `TestCheckHostManagerChartVersion`: `0.33.0`, `0.34.1` → nil; `0.32.0`, `""`, `^0.33`, `latest` → error.
  - `TestBuildHostManagerChartSpec_NoRoleRef`: values have no `roleRef` key; `os.Getenv("HOST_MANAGER_CLUSTER_ROLE")` is not read (grep test: file does not contain the string).
  - `TestHostManagerServiceAccountName`: `{}`→host; `{serviceAccount:{name:x}}`→x; `{serviceAccount:{create:false}}`→`default`; `{serviceAccount:{create:false,name:y}}`→y.
  - `TestClusterReaderSubjects` (envtest): ensure twice → one subject; ensure for a second namespace → two; remove first → one remains.
  - `TestHelmRun_UnsupportedChartVersionRefused`: host pinned `0.32.0` → no Helm call, condition reason `HostManagerChartUnsupported`, legacy objects untouched.
- [ ] **Step 2: Run** `go test ./internal/controller/ -run 'ChartVersion|NoRoleRef|ServiceAccountName|ClusterReaderSubjects|UnsupportedChartVersion' -v` — Expected: FAIL.
- [ ] **Step 3: Implement.** Delete the roleRef block and env read. Version check runs before step 1 of `runAsyncHelmReconcile`, next to `checkCompanionSources`. After a successful host-manager chart install/upgrade, `ensureClusterReaderSubject(host.Namespace, hostManagerServiceAccountName(vals, host.Name))`.
- [ ] **Step 4: Run** the Step 2 command — Expected: PASS.
- [ ] **Step 5: Commit** `feat(helm): minimum host-manager chart, cluster-reader subjects, no roleRef`.

### Task N6: Installer bootstrap, impersonated installs, lifecycle

**Files:**
- Create: `internal/controller/installer.go`
- Modify: `internal/controller/kdexhost_controller_helm.go:605-660` (bootstrap before the run, impersonated client)
- Modify: `internal/controller/kdexhost_controller.go:205-370` (teardown)
- Modify: `internal/controller/cache_options.go` (label-selected ByObject entries)
- Test: `internal/controller/installer_test.go`

**Interfaces:**
- Consumes: N1 names, N2 `HelmAsInstaller`, N5 subject helpers.
- Produces:
  - `const InstallerServiceAccountName = "kdex-installer"` (comment: must equal host-manager's constant).
  - `func (r *KDexHostReconciler) ensureInstaller(ctx context.Context, namespace string) error` — SA + RoleBinding (`roleRef ClusterRole/kcnas-operator-installer`), both labelled `app.kubernetes.io/managed-by: kcnas-operator`, RoleBinding carries finalizer `kdex.dev/installer`; no ownerRefs.
  - `func (r *KDexHostReconciler) releaseInstallerIfUnused(ctx context.Context, namespace, departingHost string) error` — when no other KDexHost (live, not terminating) remains in the namespace: remove the finalizer, delete RoleBinding and SA.
  - `func (r *KDexHostReconciler) namespaceTerminating(ctx context.Context, namespace string) (bool, error)` — APIReader Get of the Namespace.

- [ ] **Step 1: Failing tests** (envtest).
  - `TestEnsureInstaller_Idempotent`: twice → one SA, one RoleBinding with the label, the finalizer, the roleRef.
  - `TestReleaseInstaller_KeptForSiblingHost`: hosts `h1`, `h2` in `ns`; release for `h1` → SA and RoleBinding still present.
  - `TestReleaseInstaller_RemovedForLastHost`: single host → both gone.
  - `TestTeardown_NamespaceTerminatingSkipsUninstall`: namespace with deletionTimestamp (fake reader) → no `Uninstall` call; cluster-reader subject removed; host finalizer removed.
  - `TestHelmRun_UsesInstallerIdentity`: factory records identity → `HelmAsInstaller` for install/upgrade.
  - `TestCacheOptions_LabelSelectedRBACKinds`: `CacheOptions().ByObject` has entries for `ServiceAccount`, `RoleBinding`, `ClusterRoleBinding` with selector `app.kubernetes.io/managed-by=kcnas-operator`.
- [ ] **Step 2: Run** `go test ./internal/controller/ -run 'Installer|NamespaceTerminating|UsesInstallerIdentity|LabelSelectedRBAC' -v` — Expected: FAIL.
- [ ] **Step 3: Implement.** `ensureInstaller` runs in `runAsyncHelmReconcile` after `helmRunWanted` and before the first chart. Teardown order: (namespace terminating → skip Helm) else uninstall with the identity chosen in N7; then `removeClusterReaderSubject`; then `releaseInstallerIfUnused`; then remove the host finalizer. Set the cluster-reader ClusterRoleBinding's label in N1's YAML so the label-selected cache sees it.
- [ ] **Step 4: Run** the Step 2 command and the whole controller suite — Expected: PASS.
- [ ] **Step 5: Commit** `feat(helm): per-namespace installer identity and lifecycle`.

### Task N7: Legacy RBAC migration (make-before-break)

**Files:**
- Create: `internal/controller/legacy_rbac.go`
- Modify: `internal/controller/kdexhost_controller.go` (call cleanup each reconcile, outside the hash gate; uninstall identity choice)
- Test: `internal/controller/legacy_rbac_test.go`

**Interfaces:**
- Produces:
  - `func (r *KDexHostReconciler) legacyRBAC(ctx context.Context, host *kdexv1alpha1.KDexHost) (role *rbacv1.ClusterRole, binding *rbacv1.ClusterRoleBinding, err error)` — matches `ClusterRole/<host.Name>` and `ClusterRoleBinding/<host.Name>-<ns>` only when annotations `meta.helm.sh/release-name=<host.Name>` and `meta.helm.sh/release-namespace=<ns>` match, and for the binding `roleRef.name == host.Name`.
  - `func (r *KDexHostReconciler) cleanupLegacyRBAC(ctx context.Context, host *kdexv1alpha1.KDexHost) error` — deletes both **only if** `RoleBinding/<host.Name>` exists in the host namespace (proof the new chart is installed); sets/clears `LegacyRBACPresent`.
  - Uninstall identity: `HelmAsOperator` when `legacyRBAC` finds either object (record may still list them), else `HelmAsInstaller`.
  - Every function in this file carries `// Migration code: delete in release B (see the follow-up issue filed in Task N9).`

- [ ] **Step 1: Failing tests** (envtest).
  - `TestCleanupLegacy_WaitsForNewRoleBinding`: legacy pair present, no new RoleBinding → nothing deleted, condition `LegacyRBACPresent` true.
  - `TestCleanupLegacy_DeletesAfterUpgrade`: add `RoleBinding/<host>` → both legacy objects deleted, condition cleared.
  - `TestCleanupLegacy_SameNameOtherNamespaceUntouched`: host `rsi` in `a` and `b`; legacy objects annotated for `b` only → cleanup for `a` deletes nothing.
  - `TestCleanupLegacy_RunsWhenHashUnchanged`: helm status Completed with matching hash → cleanup still runs.
  - `TestTeardown_LegacyRecordUninstallsAsOperator`: legacy present → `Uninstall` called on the `HelmAsOperator` client; after it, legacy objects deleted and finalizer released.
- [ ] **Step 2: Run** `go test ./internal/controller/ -run 'CleanupLegacy|LegacyRecord' -v` — Expected: FAIL.
- [ ] **Step 3: Implement.** Call `cleanupLegacyRBAC` from `Reconcile` before `reconcileHelmReleases` on every non-deleting pass. In teardown, run the legacy uninstall path (operator identity), then delete any remaining legacy objects.
- [ ] **Step 4: Run** the Step 2 command and the whole suite — Expected: PASS.
- [ ] **Step 5: Commit** `feat(migration): make-before-break legacy RBAC cleanup`.

### Task N8: End-to-end check on a kind cluster

**Files:** none new (uses `test/e2e` harness if it covers KDexHost; else a scripted check recorded in the commit message).

- [ ] **Step 1:** On kind: install nexus **v0.7.8** + host-manager chart **0.32.0**, create a KDexHost with the `audit-sync`-shaped companion (a local OCI registry chart with one Deployment) → legacy ClusterRole + ClusterRoleBinding exist.
- [ ] **Step 2:** Upgrade to the locally built nexus + host-manager chart `0.33.0` (local registry). Expected, in order: `kdex-installer` SA + RoleBinding appear; `Role/<host>`, `RoleBinding/<host>`, function-deployer SA/Role/RoleBinding appear; legacy ClusterRole/ClusterRoleBinding deleted; cluster-reader ClusterRoleBinding lists the host-manager SA; host-manager pod Ready; `kubectl auth can-i get secrets -n kube-system --as system:serviceaccount:<ns>:<host>` → `no`.
- [ ] **Step 3:** Create a KDexFunction (executable origin) → deployer Job runs as `<host>-function-deployer`, Knative Service applied.
- [ ] **Step 4:** Delete the KDexHost → finalizer released, installer SA/RoleBinding gone, cluster-reader subject gone.
- [ ] **Step 5:** Record the transcript summary in the commit message of a docs/changelog commit, or fix forward in the owning task if any step fails.

### Task N9: Docs, release, follow-up issue

**Files:**
- Modify: `kdex-main-site/docs-app/content/src/en/` security doc (ServiceAccounts, installer, cross-namespace disabled, OCI companions)
- Modify: the kdex-kcnas skill source and installed copy (diff both first; they have diverged before)

- [ ] **Step 1:** Update docs; `make lint` at workspace root.
- [ ] **Step 2:** Run the quad over each repo's range since its last `Quad-Range` marker; fix, mark.
- [ ] **Step 3:** Tag in order: kdex-host-manager `v0.33.0` and kdex-knative-deployer (next patch), then kdex-nexus-manager (next minor). Confirm CI publishes images and charts.
- [ ] **Step 4:** Relay to infra: dev+prod first — nexus pin, `hostDefault.chart.version: 0.33.0`, deployer chart pin, in one commit; tenants (public, smg, spike2) afterwards in one commit. Ask infra to verify per cluster: `kubectl get clusterrole,clusterrolebinding -l app.kubernetes.io/name=host-manager` empty, hosts Ready, functions deploy.
- [ ] **Step 5:** File the release-B issue on kdex-tech/nexus-manager with the body from nexus `docs/release-b-privilege-cleanup.md`, and replace the marker text `(privilege-redesign follow-up issue)` with the issue reference everywhere it appears.
- [ ] **Step 6:** Close nexus #61, #62, #63, #64 citing the commits.
