// Package server is the preview-tool composition root. It wires loader →
// fakeclient → supervisor → synth → host-manager's web server into a single
// runnable HTTP listener.
//
// # Architecture note: function-proxy plumbing (§4.5 auth handling)
//
// Per spec §4.5, the preview tool does NOT mint per-function FAT audience
// tokens — the supervised child process is reached without an Authorization
// header. host-manager's stock reverseProxyHandler (host/proxy.go:107-114)
// would mint a FAT token, and its registration gate (host/host.go:404)
// short-circuits unless authConfig.ActivePair is non-nil. Both behaviors are
// production-correct but wrong for preview.
//
// Resolution: the composition root owns an outer http.ServeMux that intercepts
// each function's basePath BEFORE delegating to host-manager's web server. The
// mux routes /<basePath>/* to a stdlib httputil.NewSingleHostReverseProxy aimed
// at the supervised process URL, and falls through to host-manager's handler
// for everything else (page rendering, theme assets, importmap, etc.). The
// effect:
//
//   - synth.ApplyToHostHandler still runs — its page-render side effects make
//     HostHandler.ServeHTTP work for non-function paths.
//   - The function-mux registration inside RebuildMux is a no-op (no auth) — fine,
//     because the outer mux owns those routes anyway.
//   - No FAT minting, no JWT signing — matches §4.5 exactly.
//
// See ../../../docs/superpowers/plans/2026-06-04-kdex-cli-phase-2-preview-mvp.md
// §Task 2.7 for the broader plan context.
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	hmserver "github.com/kdex-tech/host-manager/internal/web/server"

	"github.com/kdex-tech/host-manager/internal/preview/fakeclient"
	"github.com/kdex-tech/host-manager/internal/preview/loader"
	"github.com/kdex-tech/host-manager/internal/preview/resolver"
	"github.com/kdex-tech/host-manager/internal/preview/supervisor"
	"github.com/kdex-tech/host-manager/internal/preview/synth"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// Options configures the preview Run. Zero values are accepted where noted.
type Options struct {
	// CRsDir is the path to a flat directory of YAML CR fixtures. Required.
	CRsDir string

	// Addr is the bind address (e.g. "127.0.0.1:0" or ":4000"). Required.
	Addr string

	// Host is the focal KDexInternalHost name when the snapshot contains
	// more than one. Optional when the snapshot has exactly one host.
	Host string

	// ThemeOverrides and AppOverrides are reserved for Task 2.8's
	// preview-side asset serving. The composition root accepts them so the
	// kdex preview command can pass them through unchanged; they are not
	// yet consumed.
	ThemeOverrides []resolver.ThemeOverride
	AppOverrides   []resolver.AppOverride

	// FnOverrides is the merged list of dir-form + URL-form function
	// overrides. Dir-form entries are spawned by the supervisor; URL-form
	// entries are forwarded as-is.
	FnOverrides []resolver.FnOverride

	// MissingApp / MissingFn control behavior when a referenced app/function
	// has no override. Reserved for Task 2.8 (stubs); v0 ignores them.
	MissingApp resolver.MissingAppMode
	MissingFn  resolver.MissingFnMode

	// FnStartupTimeout caps how long the supervisor will wait for each
	// child function to bind its port. Zero -> 30s (supervisor default).
	FnStartupTimeout time.Duration

	// shutdownGrace is the grace period for in-flight requests + supervisor
	// children on shutdown. Not exposed via Options yet (Task 2.7 stays
	// minimal); 5s matches the production host-manager default.
}

const (
	defaultShutdownGrace    = 5 * time.Second
	defaultSupervisorKill   = 5 * time.Second
	missingHostMultipleHint = "snapshot contains multiple KDexInternalHosts; pass --host to select one"
)

// Run boots the preview server and blocks until ctx is canceled, at which
// point it gracefully drains in-flight requests and tears down supervised
// children. Returns nil on clean shutdown.
//
// Errors during the boot pipeline (load, host pick, supervisor spawn,
// fakeclient setup, synth) are returned immediately — the caller's defer is
// responsible for cleaning up any partial state (supervisor children, etc.).
// Run owns the supervisor lifecycle: on any error after Spawn, it shuts the
// supervisor down before returning.
func Run(ctx context.Context, opts Options) error {
	logger := log.Log.WithName("preview")

	// 1. Load CRs from disk.
	snap, err := loader.Load(opts.CRsDir)
	if err != nil {
		return fmt.Errorf("load CRs: %w", err)
	}
	if len(snap.InternalHosts) == 0 {
		return errors.New("snapshot contains no KDexInternalHost")
	}

	// 2. Pick focal host.
	focal, err := pickHost(snap.InternalHosts, opts.Host)
	if err != nil {
		return fmt.Errorf("pick host: %w", err)
	}

	// 3. Construct supervisor.
	sup := supervisor.New(supervisor.Options{StartupTimeout: opts.FnStartupTimeout})
	// Always tear down supervised children on Run return. Idempotent — a
	// later explicit Shutdown call is a no-op.
	defer func() { _ = sup.Shutdown(defaultSupervisorKill) }()

	// 4. Resolve override URLs (URL form: passthrough; Dir form: spawn).
	urls := make(map[string]string, len(opts.FnOverrides))
	for _, ov := range opts.FnOverrides {
		switch ov.Kind {
		case resolver.FnOverrideURL:
			urls[ov.Name] = ov.URL
		case resolver.FnOverrideDir:
			url, spawnErr := sup.Spawn(ctx, ov)
			if spawnErr != nil {
				return fmt.Errorf("spawn function %q: %w", ov.Name, spawnErr)
			}
			urls[ov.Name] = url
		default:
			return fmt.Errorf("function override %q: unknown kind", ov.Name)
		}
	}

	// 5. Setup fake-client + run page/translation/utility reconcilers.
	// Pass the focal host name so that fakeclient's deriveFocalHostAndNamespace
	// agrees with our pickHost result — critical for multi-host snapshots where
	// opts.Host selects a non-first host.
	fc, err := fakeclient.SetupWithOptions(ctx, snap, fakeclient.SetupOptions{FocalHostName: focal.Name})
	if err != nil {
		return fmt.Errorf("fakeclient.Setup: %w", err)
	}

	// 6. Synthesize routes for the outer mux + push HostHandler state.
	routes, err := synth.SynthesizeRoutes(*focal, snap.Functions, urls)
	if err != nil {
		return fmt.Errorf("synth routes: %w", err)
	}
	if err := synth.ApplyToHostHandler(ctx, fc.HostHandler, snap, urls); err != nil {
		return fmt.Errorf("synth.ApplyToHostHandler: %w", err)
	}

	// 7. Build the host-manager web server. Address argument is recorded on
	// the returned *http.Server but we replace its Handler with our outer
	// mux below, then call ListenAndServe ourselves.
	srv := hmserver.New(opts.Addr, fc.HostHandler)

	// 8. Wrap the host-manager handler with the function-proxy outer mux.
	srv.Handler = newProxyMux(srv.Handler, routes, opts.MissingFn)

	// 9. Boot the listener and watch ctx for shutdown.
	logger.Info("starting preview server", "addr", opts.Addr, "routes", len(routes))
	listenErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		listenErr <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error(err, "graceful shutdown failed")
		}
		// Wait for the ListenAndServe goroutine to actually return (so the
		// listener is closed before we return to the caller).
		<-listenErr
		return nil
	case err := <-listenErr:
		return err
	}
}

// pickHost selects the focal KDexInternalHost from the snapshot. The rules:
//
//   - 0 hosts: caller should have errored before calling pickHost.
//   - 1 host: returned regardless of `name`.
//   - >1 hosts: `name` must match one of them (error otherwise).
func pickHost(hosts []kdexv1alpha1.KDexInternalHost, name string) (*kdexv1alpha1.KDexInternalHost, error) {
	if len(hosts) == 0 {
		return nil, errors.New("snapshot contains no KDexInternalHost")
	}
	if len(hosts) == 1 {
		return &hosts[0], nil
	}
	if name == "" {
		return nil, errors.New(missingHostMultipleHint)
	}
	for i := range hosts {
		if hosts[i].Name == name {
			return &hosts[i], nil
		}
	}
	return nil, fmt.Errorf("no KDexInternalHost named %q in snapshot", name)
}
