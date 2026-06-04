package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kdex-tech/host-manager/internal/preview/resolver"
	"github.com/kdex-tech/host-manager/internal/preview/server"
)

func NewPreviewCmd() *cobra.Command {
	var (
		crsDir    string
		addr      string
		host      string
		themes    []string
		apps      []string
		fns       []string
		missApp   string
		missFn    string
		fnTimeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Preview the KCNAS runtime locally",
		Long: `Preview renders KDexHost composition (theme + pages + archetypes +
page-headers/footers/navigation) from a directory of CRs on disk and serves
the result on a local HTTP port. Function-proxy routes resolve via the
--fn flag, either to a supervised local directory (dev-friendly) or to an
external URL (fallback for tunnels / IDE-debug processes).

Manual refresh in v1; hot reload is Phase 3.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			themeOverrides := make([]resolver.ThemeOverride, 0, len(themes))
			for _, s := range themes {
				ov, err := resolver.ParseThemeOverride(s)
				if err != nil {
					return fmt.Errorf("--theme %q: %w", s, err)
				}
				themeOverrides = append(themeOverrides, ov)
			}
			appOverrides := make([]resolver.AppOverride, 0, len(apps))
			for _, s := range apps {
				ov, err := resolver.ParseAppOverride(s)
				if err != nil {
					return fmt.Errorf("--app %q: %w", s, err)
				}
				appOverrides = append(appOverrides, ov)
			}
			fnOverrides := make([]resolver.FnOverride, 0, len(fns))
			for _, s := range fns {
				ov, err := resolver.ParseFnOverride(s)
				if err != nil {
					return fmt.Errorf("--fn %q: %w", s, err)
				}
				fnOverrides = append(fnOverrides, ov)
			}
			ma, err := resolver.ParseMissingAppMode(missApp)
			if err != nil {
				return err
			}
			mf, err := resolver.ParseMissingFnMode(missFn)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			defer signal.Stop(sig)
			go func() {
				<-sig
				fmt.Fprintln(os.Stderr, "shutdown signal received")
				cancel()
			}()

			return server.Run(ctx, server.Options{
				CRsDir:           crsDir,
				Addr:             addr,
				Host:             host,
				ThemeOverrides:   themeOverrides,
				AppOverrides:     appOverrides,
				FnOverrides:      fnOverrides,
				MissingApp:       ma,
				MissingFn:        mf,
				FnStartupTimeout: fnTimeout,
			})
		},
	}
	cmd.Flags().StringVar(&crsDir, "crs", "", "Directory containing KDex CR YAMLs (required)")
	cmd.Flags().StringVar(&addr, "addr", ":8080", "HTTP listen address")
	cmd.Flags().StringVar(&host, "host", "", "KDexInternalHost name (required if >1 in --crs)")
	cmd.Flags().StringArrayVar(&themes, "theme", nil, "Theme override: name=<path|URL>, repeatable")
	cmd.Flags().StringArrayVar(&apps, "app", nil, "App override: name=<path|URL>, repeatable")
	cmd.Flags().StringArrayVar(&fns, "fn", nil, "Function override: name=<dir|URL>, repeatable")
	cmd.Flags().StringVar(&missApp, "missing-app", "placeholder", "Behavior for unresolved apps: placeholder|skip|error")
	cmd.Flags().StringVar(&missFn, "missing-fn", "placeholder", "Behavior for unresolved functions: placeholder|skip|error")
	cmd.Flags().DurationVar(&fnTimeout, "fn-startup-timeout", 30*time.Second, "Wait for supervised functions to bind their port")
	_ = cmd.MarkFlagRequired("crs")
	return cmd
}
