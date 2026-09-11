# kdex-host
// TODO: Add simple overview of use/purpose

## Description
// TODO: An in-depth paragraph about your project and overview of use

## Getting Started

### Prerequisites
- go version v1.24.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-buildx-local PLATFORMS=linux/amd64 REPOSITORY=k3d-registry:5000 IMG=kdex-tech/kdex-host
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/kdex-host:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/kdex-host:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/kdex-host/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
kubebuilder edit --plugins=helm/v1-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## Auth Event Hooks (`http-event-hook` Secret)

The host-manager can notify (advisory) or gate (enforcing) external HTTP
endpoints on auth lifecycle events — login, logout, login-failed, and
session-refresh. One or more Secrets configure the hooks; each hook is a
separate Secret, discovered by the `kdexinternalhost` controller alongside
the `http-lookup-auth` Secret.

A Secret is picked up as an event hook when it:

- is annotated with `kdex.dev/secret-type: http-event-hook`
- is annotated with `kdex.dev/active-key: "true"`

Unlike `http-lookup-auth` (only the newest active one is used), **every**
active `http-event-hook` Secret becomes a hook — multiple hooks may run
side by side. When more than one enforcing hook subscribes to the same
event, they are evaluated in Secret-name order (sorted lexicographically).

### Data keys

| key | required | default | meaning |
|---|---|---|---|
| `url` | yes | — | endpoint POSTed for each subscribed event |
| `shared-secret` | yes | — | HMAC-SHA256 key; must be at least 32 raw bytes |
| `events` | yes | — | comma-separated subset of `login`, `logout`, `login-failed`, `session-refresh` |
| `mode` | no | `advisory` | `advisory` or `enforcing`; `enforcing` is only honored for `login`/`logout` — for `login-failed`/`session-refresh` it is silently treated as advisory (both are always fired async) |
| `timeout-ms` | no | `2000` | integer milliseconds; bounds every call to this hook, sync and async |
| `failure-mode` | no | per-event (see below) | `fail-open` or `fail-closed`; only meaningful for enforcing hooks |

### Request contract

```
POST <url>
Content-Type: application/json
X-K-CNAS-Event-Timestamp: <unix-millis>
X-K-CNAS-Event-Signature: hex(hmac-sha256(shared-secret, timestamp + "." + body))
```

The endpoint MUST verify the HMAC over `timestamp + "." + body` (same
convention as the `http-lookup-auth` Secret's `X-K-CNAS-Lookup-*` headers).

Body envelope:

```json
{
  "event": "login",              // login | logout | login-failed | session-refresh
  "timestamp": 1699999999999,    // unix millis, matches the signature timestamp
  "host": "acme.example",        // the KDexHost identity
  "subject": "alice",            // sub; may be "" for logout when no token could be decoded
  "auth_method": "local",        // local | oidc | ... (omitted when unknown)
  "client_id": "…",              // omitted when not applicable
  "scope": "openid profile …",   // omitted when not applicable
  "claims": { "…": "…" },        // populated for login/session-refresh (minus roles/entitlements, which are broken out below); best-effort/omitted for logout; absent for login-failed
  "roles": ["…"],                // omitted when empty
  "entitlements": ["…"],         // omitted when empty
  "session_id": "…",             // refresh/session id, where available; omitted otherwise
  "reason": "…"                  // login-failed only: why the login failed
}
```

Fields are `omitempty` — a hook only sees the keys that apply to the event
that fired it. For `logout`, identity is recovered best-effort by decoding
the refresh/session token before it is cleared; if no token is available,
`subject` (and the other identity fields) are simply absent and the event
still fires.

### Response contract

Read **only** for **enforcing `login`**:

```json
{ "ok": true, "reason": "" }
```

- `ok: false` denies the login; `reason` (default `"denied"` when empty) is
  surfaced as the login failure reason.
- For advisory calls, all async-only events (`login-failed`,
  `session-refresh`), and enforcing `logout`, the response body is ignored —
  only delivery (a 2xx status that decodes) is tracked, and failures are
  logged, never surfaced to the caller.

### Advisory vs. enforcing, and failure modes

- **Advisory** hooks fire in a background goroutine, best-effort, bounded by
  `timeout-ms`. A failure (timeout, dial error, non-2xx, decode failure) is
  logged and never affects the auth flow. `login-failed` and
  `session-refresh` are *always* dispatched this way, regardless of a hook's
  configured `mode`.
- **Enforcing `login`** hooks run inline on the login path, sequentially in
  Secret-name order, short-circuiting on the first `ok: false`; every
  enforcing hook must return `ok: true` for the login to proceed
  (`ErrLoginHookDenied`). On a transport/timeout/decode failure, the
  effective `failure-mode` decides: **default is `fail-closed`** (deny the
  login with a generic reason) — only an explicit `failure-mode:
  fail-open` on that hook's Secret allows the login through when the hook is
  unreachable.
- **Enforcing `logout`** hooks run as sequential *barriers*, each bounded by
  its own `timeout-ms`, but **never refuse the logout** — a failure (or an
  `ok: false` response) is logged and logout proceeds regardless of
  `failure-mode`. Advisory `logout` hooks fire async afterward.

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

