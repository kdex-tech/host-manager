# Privilege redesign: the namespace is the unit of security

Date: 2026-11-11
Repos: kdex-nexus-manager, kdex-host-manager, kdex-knative-deployer.
**No kdex-crds change** (a goal; see G8).
Closes: nexus-manager #61, #62, #63, #64.
Reviewed: builder check + quad (data integrity, performance, security, DRY) over
the first draft, 2026-11-11; findings folded in below.

## Intent

Follow least privilege across the KDex control plane. This is a principle, not a
response to one attack: every identity (nexus, each host-manager, the deployer and
observer, kpack builds, Helm installs) holds only the permissions its job uses,
only where it uses them.

**Trust model (decided by the user):**

- **The namespace is the unit of security.** Everything authored into one
  namespace (KDexHost, KDexFunctions, Secrets, companion charts, host-manager
  values) passes one gate: code review in Git, applied by Argo/infra. Inside a
  namespace, parties trust each other.
- Kubernetes has no trust boundary inside a namespace (anyone who can create a Pod
  there can read every Secret and act as any ServiceAccount there), so this design
  does not build one. Per-function Secret consent, function SA/volume restrictions
  and similar intra-namespace narrowing are **out of scope**.
- **The operator** (whoever installs nexus, writes its configuration and the
  cluster-scoped KDexCluster* content) is trusted cluster-wide.
- **Nothing in one namespace may reach another.** Cross-namespace references are
  **disabled** in this release (user decision). The concept is kept: a later
  release may re-enable it as an opt-in that the *target* namespace must grant.

**Defaults are least privilege; knobs stay where there is a real use case**
(user's rule). **A host MUST keep control of its own host-manager chart version
and values** (user's rule). Anything a host controls may only affect its own
namespace.

## Why now (inventory, 2026-11-11)

1. **Every host-manager is bound cluster-wide.** The nexus chart emits
   `HOST_MANAGER_CLUSTER_ROLE` only when `controllerManager.container.env` is
   non-empty (`kdex-nexus-manager/chart/templates/manager/manager.yaml:67-80`); no
   deployment sets it, so each host-manager release renders its **own ClusterRole
   named `host.Name`** plus a **ClusterRoleBinding**. Live on rsi-gke-cluster:
   `rsi-dev-dev -> rsi-dev`, `rsi-prod-prod -> rsi-prod`. Each host-manager can read
   and write Secrets, Deployments, Jobs, etc. in every namespace.
2. **host-manager's token is mounted into pods it does not author:** the deployer
   Job and observer CronJob (`kdex-host-manager/internal/deploy/deploy.go:419,444,
   521-550`; images from the FaaSAdaptor) and, when a function sets no builder SA,
   kpack builds (`kdexfunction_controller.go:271,1426-1436`). With (1) that token
   works cluster-wide.
3. **nexus installs Helm releases with its own cluster-wide role,** including
   `create` on ClusterRoles/ClusterRoleBindings (held only so the escalation guard
   accepts the per-host ClusterRole). Companion charts install with that power.
4. **Cross-namespace reads with no consent from the target:** nexus
   `ResolveSecret` / `ResolveKDexObjectReference` honour a reference's namespace
   (`kdex-nexus-manager/internal/controller/resolver_common.go:253-255,343-349`);
   host-manager allows references into `spec.referenceNamespaces`, which the host
   author names unilaterally; a namespaced KDexFaaSAdaptor in another namespace
   supplies the images and SA choices for Jobs run in the host's namespace.
5. **Companion chart loading leaks across tenants** (#61-#64).
6. Per-host ClusterRoles are named only `host.Name`, so same-named hosts in
   different namespaces collide.

## Goals

- G1. No host-manager holds any permission outside its own namespace, except
  read-only on cluster-scoped KDexCluster* content.
- G2. host-manager's ServiceAccount token is never mounted into a pod running an
  image host-manager does not control.
- G3. Helm installs for a host run as a namespace-scoped identity; nexus never
  holds a permission only so a release can be granted it.
- G4. Cross-namespace references are refused (Secrets and objects), except the
  Gateway API `parentRefs` attachment.
- G5. Companion charts are OCI only, memory-bounded, isolated per tenant
  (#61-#64).
- G6. Grants match code, with one source of truth per role and a mechanical drift
  check.
- G7. A host keeps control of its host-manager chart version and values.
- G8. No kdex-crds change; controller-side checks instead of schema changes.

## Non-goals

- Any trust boundary inside a namespace.
- Re-enabling cross-namespace references (later release; notes at the end).
- Narrowing nexus's own cluster-wide **read** access; nexus is the trusted operator.
- Moving functions into a namespace separate from their host.
- Replacing the inline `KDexFunction.spec.origin.generator` with a reference.

## Anti-goals

- A namespace author can reach another namespace or cluster scope.
- Silent breakage of a live host. All live hosts and companions keep working, with
  no per-tenant manual step beyond the usual single infra pin commit.
- A migration that leaves a legacy per-host ClusterRole/ClusterRoleBinding behind,
  or leaves migration code in place forever.

## Constraints (live facts, infra + rsi, 2026-11-11)

- Live tenants: rsi-gke-cluster (dev, prod), public, smg, spike2. spike1 was
  destroyed 2026-08-12 and receives nothing.
- No KDexHost pins `spec.helm.hostManager.version`; all take the operator default
  (tenants `config.hostDefault.chart.version` 0.31.0; dev/prod terraform
  `host_manager_version` 0.32.0).
- No cluster sets nexus `defaultNpmSecretRef` / `defaultImageSecretRef`.
- No live CR references an object or Secret in another namespace. The only
  cross-namespace references are KDexHost / KDexInternalHost routing `parentRefs`
  to `traefik/rsi-gateway` (a Gateway API attachment governed by the Gateway's
  `allowedRoutes`, not a host-manager read). No KDexHost sets `referenceNamespaces`.
- Companions: every one is `oci://`, exact semver, no `repository`, no hooks,
  nothing cluster-scoped, nothing outside the release namespace.
  - `audit-sync`: Deployment.
  - `blobsqlite`: Deployment, Service, KDexFunction (pre-created WI SA).
  - `eum` (release `eumgr`): ConfigMaps, Deployment, Service, ServiceAccount,
    KDexApp, KDexFunctions, KDexHostExtension, KDexPages, KDexRoles,
    KDexRoleBinding, KDexTranslations.
  - Not a companion: smg `delta-replicator` (hand-installed) renders a Role +
    RoleBinding and NetworkPolicies. If it ever becomes a companion, the installer
    knob (D2) covers it.
- Live host-manager values overrides touch env, resources, extraArgs, timeouts,
  scheduling, valkey storage. The chart renders the valkey subchart (Deployment,
  Service, ConfigMap, ServiceAccount, PVC).
- The live default KDexClusterFaaSAdaptor (rendered by the kdex-knative-deployer
  chart, `chart/templates/faas-adaptor.yaml:12,25`) sets `deployer/observer.
  serviceAccountName` to an SA in the deployer chart's namespace; host-manager
  ignores both fields today.
- Helm SDK: impersonation via `cli.EnvSettings.KubeAsUser` (set before
  `actionConfig.Init`); nexus caches Helm clients per host
  (`kdexhost_controller.go:916-942`). Helm v4 upgrade silently skips a dropped
  resource it cannot `Get` (any error, Forbidden included;
  `pkg/kube/client.go` Update), and uninstall fails on Forbidden.
- nexus's memory limit is tight (`config/manager/manager.yaml:97`, 128Mi; chart
  allows more); its cache is cluster-wide except Secrets
  (`internal/controller/cache_options.go:25-41`).

## Design

### D1. host-manager's permissions ship with its chart, as namespaced RBAC

- The host-manager chart renders **namespaced `Role` + `RoleBinding`** objects in
  the host namespace, never a ClusterRole or ClusterRoleBinding:
  - `<fullname>` Role for host-manager's own SA;
  - `<fullname>-function-deployer` Role + SA for the deployer and observer (D3).
- **One source per role.** The host-manager Role's rules are generated from
  host-manager's `+kubebuilder:rbac` markers (`controller-gen rbac` into the chart
  template via a make target); CI fails if the chart and the generated output
  differ. `config/rbac/role.yaml` stays the generated file. The deployer Role has
  one hand-maintained source in the chart, with a comment per rule citing the
  kdex-knative-deployer call that needs it.
- Because the RBAC ships with the chart, **any chart version a host pins carries
  exactly the permissions it needs** (G7). No union role, no cross-repo copy.
- **Cluster-scoped reads** (get/list/watch on KDexCluster* kinds): the nexus chart
  ships one fixed ClusterRole `kcnas-operator-host-manager-cluster-reader` and
  **one fixed ClusterRoleBinding** to it. nexus maintains its subject list (one
  entry per host-manager SA), adding on host install and removing in the host
  finalizer. nexus may only `get/update/patch` that one ClusterRoleBinding
  (`resourceNames`). No per-host ClusterRoleBinding exists.
  The binding watch also needs list/watch on it: release A grants those through
  the broad clusterrolebindings line; release B must add `list;watch` to the
  `resourceNames` line.
- Deleted from host-manager's chart: `clusterrole.yaml`, `clusterrolebinding.yaml`,
  the `roleRef` value and its `if not .Values.roleRef.name` branch. Deleted from
  nexus: the `HOST_MANAGER_CLUSTER_ROLE` env var and its gated chart block,
  `chart/templates/rbac/host-controller-role.yaml`,
  `config/rbac/host-controller-role.yaml`, and the roleRef code
  (`kdexhost_controller_helm.go:969-978`).
- **Grant corrections** (re-derived from code by the builder; the inventory found):
  remove persistentvolumeclaims, gateways, serving.knative.dev (moves to the
  deployer Role), kpack `images/finalizers` and `images/status`, and the unused
  verbs (patch on secrets/configmaps/services/deployments/cronjobs/httproutes/
  ingresses; update+patch on jobs; delete on secrets/configmaps/httproutes/
  ingresses/kdexfunctions; create/update/patch/delete on kdexinternalhosts;
  create/patch/delete on kdexinternaltranslations/kdexinternalutilitypages/
  kdexpages; update on kpack images; patch on non-function status; finalizers on
  kdexpages/kdexinternaltranslations/kdexinternalutilitypages). The remaining
  `/finalizers` grants carry a marker comment: needed for `blockOwnerDeletion`
  when OwnerReferencesPermissionEnforcement is enabled.
- Delete host-manager's dead ServiceAccount watch
  (`kdexinternalhost_controller.go:976-978`, jsonpath on a removed field).

### D2. Helm installs run as a per-namespace installer identity

- For each host namespace, nexus itself ensures a ServiceAccount `kdex-installer`
  and a RoleBinding to the fixed ClusterRole `kcnas-operator-installer`, both
  labelled as nexus-owned.
- nexus performs every Helm action for a host (host-manager release and
  companions: install, upgrade, uninstall, release-storage Secrets) while
  impersonating `system:serviceaccount:<ns>:kdex-installer` (`KubeAsUser` on the
  cached per-host client).
- `kcnas-operator-installer` covers what the live charts render in their own
  namespace: core configmaps, services, serviceaccounts, persistentvolumeclaims,
  secrets; apps deployments; the namespaced kdex.dev kinds companions render;
  and **`rbac` roles + rolebindings with `escalate` and `bind`**, so the
  host-manager chart can create its Roles. A RoleBinding grants a ClusterRole's
  rules in one namespace only, so the installer can grant anything **inside its
  namespace** and nothing outside it: exactly the trust model. Exact rule list is
  derived from the rendered charts by the builder.
- **Knob:** `kcnas-operator-installer` is an aggregated ClusterRole
  (`aggregationRule` on label `kdex.dev/aggregate-to-installer: "true"`). An
  operator extends it by applying a labelled ClusterRole (the delta-replicator
  case). No configuration field, no nexus code.
- **Lifecycle (no ownerRefs):** several hosts may share a namespace, so the
  installer SA and RoleBinding are not owned by a host. nexus removes them
  after the last host in the namespace has finished teardown. (Quad B1: no
  finalizer on the installer RoleBinding -- it protected nothing, and a nexus
  rollback would leave it holding namespace deletion.) When the namespace is terminating, nexus skips the Helm
  uninstall (the namespace deletion removes everything) and only removes what it
  owns outside the namespace (the cluster-reader subject).
- nexus's new grants: `impersonate` on serviceaccounts with
  `resourceNames: [kdex-installer]`; get/list/watch/create/update/delete on
  serviceaccounts and rolebindings; `bind` on clusterroles with
  `resourceNames: [kcnas-operator-installer]`; get/update/patch on the
  cluster-reader ClusterRoleBinding (`resourceNames`), plus list/watch on it for
  the binding watch (release A: the broad line; release B: add to this one).
- **nexus cache:** everything nexus creates carries a nexus-owned label, and
  `CacheOptions.ByObject` adds label-selected entries for ServiceAccount,
  RoleBinding and ClusterRoleBinding, so no cluster-wide informer on those kinds.
- **Accepted residual:** nexus, as the trusted operator, can still bootstrap an
  installer in any namespace. Tenants cannot steer it (the namespace is always the
  host's). A ValidatingAdmissionPolicy limiting nexus to labelled tenant
  namespaces is a possible later hardening, not part of this release.

### D3. Deployer and observer get their own ServiceAccount

- host-manager launches the deployer Job and observer CronJob with the chart's
  `<fullname>-function-deployer` SA, never its own (G2).
- The deployer Role grants exactly what kdex-knative-deployer calls in the host
  namespace: `serving.knative.dev/services` get + patch (server-side apply; add
  `create` if SSA creation needs it, builder verifies), `kdexfunctions` get/list
  and `kdexfunctions/status` patch, `kpack.io/images` get/patch, `kpack.io/builds`
  get (missing today, so kpack auto-recovery always fails), `pods` get.
- The observer's cluster-scoped `nodes` lookup (`kdex-knative-deployer`
  `cmd/retry.go:230-234,305`) is **removed**, not granted: it has always failed
  with Forbidden, and the pod-reason signals already cover preemption.
- `KDexFaaSAdaptor.spec.deployer/observer.serviceAccountName` stay **ignored**
  (no CRD change). The kdex-knative-deployer chart stops setting them and drops its
  own ClusterRole/ClusterRoleBinding (`chart/templates/rbac.yaml`) after the
  builder confirms nothing uses it.

### D4. Cross-namespace references are disabled

- **nexus resolvers** (`ResolveKDexObjectReference`, `ResolveSecret`) refuse a
  reference whose namespace differs from the referrer's. The refusal happens
  **before any `Get`**, with one uniform message, so status never reveals whether
  an object exists in another namespace. Cluster-scoped referrers may reference
  only cluster-scoped objects. References set in nexus's own configuration
  (`defaultNpmSecretRef`, `defaultImageSecretRef`) are operator-authored and
  exempt; none is set today.
- **`KDexHost.spec.referenceNamespaces` stays in the schema.** When non-empty,
  nexus sets a `ReferenceNamespacesDisabled` condition on the host and passes an
  empty list to host-manager, whose existing `checkReferenceNamespace` then admits
  only the host's own namespace (`reference_namespaces.go:61-66`).
- **FaaSAdaptor:** a host or function may use a namespaced KDexFaaSAdaptor only
  from its own namespace; across namespaces, only KDexClusterFaaSAdaptor.
- **Exempt:** routing `parentRefs` to a Gateway (a Gateway API attachment).
- Live impact: none (no live cross-namespace reference).

### D5. Companion charts: OCI only, bounded, isolated (#61-#64)

- nexus refuses (status condition, no install) any companion whose `chart` does
  not start with `oci://`, or which sets `repository` (#62, #63). Controller check
  only, no CRD change.
- `AddRepository` and the process-wide repository alias file are removed (#64);
  the chart-archive cache key includes the full OCI reference.
- **Memory budget (#61):** `archive.MaxDecompressedChartSize` /
  `MaxDecompressedFileSize` are set from a flag, with the default derived as a
  budget against the memory limit (cap x render overhead must fit), documented the
  way `RegistryFetchMaxBytes` is.
- Prune/teardown stop decoding every release: `ListReleases` is replaced by a
  metadata-only list of the Helm release-storage Secrets selected by the companion
  labels Helm already persists.
- Companions install through D2's installer.

### D6. kpack builds never fall back to host-manager's SA

- An empty build SA (no inline `builder.serviceAccountName`, no FaaSAdaptor builder
  default) refuses the build with a condition (`kdexfunction_controller.go:
  1426-1436`). Live: every knowdrive-site source function sets `kdex-builder`;
  the builder confirms tenant functions (blobsqlite, eum) do too.

### D7. host-manager's token stays out of pods it does not control (G2), in code

Values stay free (G7), so the guard lives in host-manager:
- One shared refusal list: host-manager's own SA, `kdex-installer`, and the
  function-deployer SA. Applied to function `serviceAccountName`, builder SA, and
  backend Deployment SA (`kdexinternalhost_controller.go:1690,1866`).
- Backend Deployments set `automountServiceAccountToken: false`, as the packages
  and codegen Jobs already do.

### D8. nexus's own role

- Remove: clusterroles create/update/patch, clusterrolebindings create (delete on
  legacy objects stays for the migration only); replicasets; every grant that
  existed only as the escalation mirror or for companions (configmaps, PVCs,
  services, jobs, cronjobs, endpointslices, gateways, httproutes, ingresses, kpack,
  knative, deployment writes, kdex write verbs on kinds nexus does not write, dead
  finalizers and status grants).
- Keep: get/list/watch on what its reconcilers read; the kdex.dev writes it makes
  (`kdexhosts` finalizer/status, `kdexinternalhosts`, `kdexinternaltranslations`,
  `kdexinternalutilitypages`, content-kind status); the D2 grants.
- `config/rbac/role.yaml` (generated from nexus markers) is the single source; the
  chart copy is regenerated from it with a CI drift check.

## Migration

Make-before-break; no window without RBAC.

1. **Minimum chart version.** The first redesigned host-manager chart version is
   the minimum. A host whose effective chart version is below it is refused with a
   condition, and nexus leaves its legacy RBAC untouched. The operator default is
   raised to that version in the same infra commit as the nexus pin.
2. **Upgrade first.** The impersonated upgrade creates the namespaced Roles,
   RoleBindings and deployer SA. Helm skips the legacy ClusterRole/
   ClusterRoleBinding it can no longer read and drops them from the release record.
3. **Then clean up, unconditionally.** On every reconcile, outside the release-hash
   gate, and before any uninstall, nexus deletes legacy objects matched by Helm
   ownership annotations (`meta.helm.sh/release-name=<host>`,
   `meta.helm.sh/release-namespace=<ns>`) and, for the binding,
   `roleRef.name == <host>`, so a same-named host in another namespace is never
   touched. Cleanup also requires the release's latest revision to be `deployed`
   and the host-manager Deployment's ServiceAccount, as recorded by nexus, to be
   a subject of the cluster-reader binding. A `LegacyRBACPresent` condition stays on the host until both are gone.
   **Teardown of a host whose release record still lists the legacy RBAC**
   (quad A1): there is no operator Helm identity; every Helm action, uninstall
   included, impersonates the namespace's installer. nexus first deletes the
   legacy objects itself (UID-pinned, matched as above, never by the record),
   then rewrites the latest release revision's stored manifest through the
   installer's Helm storage, dropping its ClusterRole, ClusterRoleBinding and
   list-typed documents, then uninstalls as the installer. The rewrite only
   keeps the uninstall from tripping over what is already gone; it authorizes
   nothing: the record is a Secret whoever writes Secrets in the namespace can
   forge, and a record re-forged after it acts with the installer's
   namespace-bounded rights only -- one listing anything else fails the
   uninstall closed (finalizer kept, "Deletion is blocked").
4. **Remove the migration.** A follow-up nexus release deletes the cleanup step,
   the `LegacyRBACPresent` condition and nexus's remaining `delete` on
   clusterroles/clusterrolebindings, once infra confirms none remain
   (`kubectl get clusterrolebinding,clusterrole -l app.kubernetes.io/name=host-manager`
   prints nothing on every cluster). File that issue when the release ships and
   cite it in a comment on the cleanup code.
5. **Release order:** host-manager and kdex-knative-deployer first (charts
   published), then nexus. Infra repins dev+prod first (nexus + operator default
   chart version + deployer chart together), then the tenants in one commit.

## Left to the builder

- Exact rule lists, derived from code and the rendered charts (host-manager,
  valkey, live companions), within the single-source rules of D1 and D8.
- Whether SSA creation of a Knative Service needs `create`.
- The minimum-version check's form (semver compare on the effective version).
- Test strategy: a chart render test that no cluster-scoped RBAC is rendered; a
  test that `CacheOptions` and the cluster-reader role cover what host-manager
  reads; envtest for the cross-namespace refusals and the installer lifecycle;
  the CI drift checks.
- Docs: kdex-main-site security docs and the kdex-kcnas skill (ServiceAccount
  rules, referenceNamespaces disabled, companions OCI-only, installer knob).

## Calls I made (for the user to check)

- host-manager's RBAC as namespaced Roles shipped in its own chart, created by an
  installer allowed `escalate`/`bind` inside its namespace (follows from G7).
- One fixed cluster-reader ClusterRoleBinding whose subjects nexus maintains,
  instead of per-host ClusterRoleBindings.
- The installer knob is Kubernetes role aggregation, not a configuration field.
- `deployer/observer.serviceAccountName` stay ignored; the observer `nodes`
  lookup is removed rather than granted.
- Companion `repository` refused by the controller, not removed from the schema
  (keeps G8).
- Operator configuration Secret references exempt from the cross-namespace refusal.
- Namespaced FaaSAdaptors usable only within their own namespace.
- nexus's residual ability to bootstrap an installer anywhere is accepted
  (operator is trusted); admission-policy hardening deferred.

## Notes for re-enabling cross-namespace references later

From the quad over the first draft:
- Opt-in lives in the target namespace (Gateway API `ReferenceGrant` pattern).
- A grant is all-or-nothing per namespace for host-manager's cache: it caches every
  non-host-only kind there, including Services and EndpointSlices
  (`kdex-host-manager/cmd/main.go:583-631`), so per-kind grants cannot be honoured
  by a fixed reader role.
- Ordering: on admit, create the reader RoleBinding before the values include the
  namespace; on revoke, roll host-manager without it before deleting the binding.
- Grants must be checked against the consuming host's namespace for content
  copied into it (transitive chains A -> B -> C).
- Referencing another namespace's executable content (apps, scripts, adaptors,
  backend images) means trusting it with execution in yours; say so in the grant.
