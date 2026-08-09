/*
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
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	"go.uber.org/zap/zapcore"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8s_runtime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	kdexlog "kdex.dev/crds/log"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/controller"
	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/web/server"

	_ "net/http/pprof"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = k8s_runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(kdexv1alpha1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))
	utilruntime.Must(configuration.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	start := time.Now()

	var cacheAddr string
	var configFile string
	var focalHost string
	namedLogLevels := make(kdexlog.NamedLogLevelPairs)
	var pprofAddr string
	var requeueDelaySeconds int
	var serviceName string
	var webserverAddr string

	var enableHTTP2 bool
	var metricsAddr string
	var metricsCertKey, metricsCertName, metricsCertPath string
	var probeAddr string
	var proxyDialTimeout time.Duration
	var proxyResponseHeaderTimeout time.Duration
	var proxyIdleConnTimeout time.Duration
	var refreshGraceWindow time.Duration
	var serverReadHeaderTimeout time.Duration
	var serverReadTimeout time.Duration
	var serverWriteTimeout time.Duration
	var serverIdleTimeout time.Duration
	var serverStreamStallTimeout time.Duration
	var secureMetrics bool
	var tlsOpts []func(*tls.Config)
	var webhookCertKey, webhookCertName, webhookCertPath string

	flag.StringVar(&cacheAddr, "cache-address", os.Getenv("CACHE_ADDRESS"), "The address of the Redis/Valkey cache. "+
		"Or set CACHE_ADDRESS env var.")
	flag.StringVar(&configFile, "config-file", "/config.yaml", "The path to a configuration yaml file.")
	flag.StringVar(&focalHost, "focal-host", "", "The name of a KDexHost resource to focus the controller instance's "+
		"attention on.")
	flag.Var(&namedLogLevels, "named-log-level", "Specify a named log level pair (format: NAME=LEVEL) (can be used "+
		"multiple times). Or set NAMED_LOG_LEVELS env var with space delimited pairs with the same format.")
	flag.StringVar(&pprofAddr, "pprof-bind-address", os.Getenv("PPROF_BIND_ADDRESS"), "The address the pprof endpoint "+
		"binds to. If not set, the pprof endpoint is disabled. Or set PPROF_BIND_ADDRESS env var.")
	flag.IntVar(&requeueDelaySeconds, "requeue-delay-seconds", 15, "Set the delay for requeuing reconciliation loops")
	flag.StringVar(&serviceName, "service-name", "", "The name of the controller service so it can self configure an "+
		"ingress/httproute with itself as backend.")
	flag.StringVar(&webserverAddr, "webserver-bind-address", ":8090", "The address the webserver binds to.")

	flag.DurationVar(&proxyDialTimeout, "proxy-dial-timeout", 5*time.Second,
		"Connection-establishment timeout for the KDexFunction reverse-proxy transport.")
	flag.DurationVar(&proxyResponseHeaderTimeout, "proxy-response-header-timeout", 60*time.Second,
		"Wait for the backend's response headers before failing. Default covers a typical Knative "+
			"scale-from-zero cold start (gRPC + cloudsqlconn + OTel); bump higher for heavier functions.")
	flag.DurationVar(&proxyIdleConnTimeout, "proxy-idle-conn-timeout", 90*time.Second,
		"How long an unused keep-alive connection lingers in the proxy transport's pool.")

	srvDefaults := server.DefaultTimeouts()
	flag.DurationVar(&serverReadHeaderTimeout, "server-read-header-timeout", srvDefaults.ReadHeaderTimeout,
		"How long the inbound webserver waits for a request's headers. 0 disables the deadline.")
	flag.DurationVar(&serverReadTimeout, "server-read-timeout", srvDefaults.ReadTimeout,
		"How long the inbound webserver allows for reading a whole request. 0 disables the deadline.")
	flag.DurationVar(&serverWriteTimeout, "server-write-timeout", srvDefaults.WriteTimeout,
		"Connection-level write deadline for the inbound webserver. A chunked response that "+
			"keeps making progress has its per-request deadline pushed forward on every explicit "+
			"Flush; a handler that writes without flushing stays bounded. text/event-stream runs "+
			"on --server-stream-stall-timeout instead. See kdex-tech/host-manager#167. "+
			"0 disables the deadline entirely (and with it all per-request adjustment).")
	flag.DurationVar(&serverIdleTimeout, "server-idle-timeout", srvDefaults.IdleTimeout,
		"How long an idle keep-alive connection to the inbound webserver lingers. 0 disables the deadline.")
	flag.DurationVar(&serverStreamStallTimeout, "server-stream-stall-timeout", srvDefaults.StreamStallTimeout,
		"Sliding write deadline for a text/event-stream response, pushed forward on every "+
			"explicit Flush. Its own, much larger window than --server-write-timeout because an "+
			"SSE keep-alive cadence belongs to the backend — but a window still reclaims a stream "+
			"whose consumer stopped reading. 0 clears the deadline for SSE outright (unbounded "+
			"until TCP keepalive; see kdex-tech/host-manager#167).")

	flag.DurationVar(&refreshGraceWindow, "refresh-grace-window", 10*time.Second,
		"How long a rotated refresh token's result stays replayable, so concurrent refreshes "+
			"from one client do not race (RFC 9700 4.14). Exactly one rotation still occurs; "+
			"losers replay the winner's pair. 0 restores strict single-winner rotation. "+
			"Clamped to at most 1m: a longer window turns single-use rotation into replay.")

	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	if err := loadLogLevelsFromEnv(&namedLogLevels); err != nil {
		panic(err)
	}

	if zapEncoderEnv := os.Getenv("ZAP_ENCODER"); zapEncoderEnv != "" {
		enc := flag.CommandLine.Lookup("zap-encoder")
		if enc != nil {
			if err := enc.Value.Set(zapEncoderEnv); err != nil {
				panic(err)
			}
		}
	}

	if zapLogLevelEnv := os.Getenv("ZAP_LOG_LEVEL"); zapLogLevelEnv != "" {
		enc := flag.CommandLine.Lookup("zap-log-level")
		if enc != nil {
			if err := enc.Value.Set(zapLogLevelEnv); err != nil {
				panic(err)
			}
		}
	}

	if zapStacktraceLevelEnv := os.Getenv("ZAP_STACKTRACE_LEVEL"); zapStacktraceLevelEnv != "" {
		enc := flag.CommandLine.Lookup("zap-stacktrace-level")
		if enc != nil {
			if err := enc.Value.Set(zapStacktraceLevelEnv); err != nil {
				panic(err)
			}
		}
	}

	if zapTimeEncodingEnv := os.Getenv("ZAP_TIME_ENCODING"); zapTimeEncodingEnv != "" {
		if zapTimeEncodingEnv == "offset" {
			opts.TimeEncoder = func(t time.Time, pae zapcore.PrimitiveArrayEncoder) {
				pae.AppendString(t.Sub(start).String())
			}
		} else {
			enc := flag.CommandLine.Lookup("zap-time-encoding")
			if enc != nil {
				if err := enc.Value.Set(zapTimeEncodingEnv); err != nil {
					panic(err)
				}
			}
		}
	}

	logger, err := kdexlog.New(&opts, namedLogLevels)
	if err != nil {
		panic(err)
	}
	ctrl.SetLogger(logger)

	setupLog.Info("named log levels", "levels", namedLogLevels)

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName,
			"webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName,
			"metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	controllerNamespace := controller.ControllerNamespace()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Controller: config.Controller{
			Logger: logger,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         false,
		Logger:                 logger,
		Metrics:                metricsServerOptions,
		Scheme:                 scheme,
		WebhookServer:          webhookServer,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	conf := configuration.LoadConfiguration(configFile, scheme)

	var cacheManager cache.CacheManager
	if cacheAddr != "" {
		var err error
		cacheManager, err = cache.NewCacheManager(cacheAddr, focalHost, nil)
		if err != nil {
			setupLog.Error(err, "unable to create cache")
			os.Exit(1)
		}
		setupLog.Info("Using cache service", "cache-address", cacheAddr)
	} else {
		cacheManager, _ = cache.NewCacheManager("", "", nil)
	}

	hostHandler := host.NewHostHandler(mgr.GetClient(), focalHost, controllerNamespace, logger.WithName("host"), cacheManager).
		SetProxyTimeouts(host.ProxyTimeouts{
			DialTimeout:           proxyDialTimeout,
			ResponseHeaderTimeout: proxyResponseHeaderTimeout,
			IdleConnTimeout:       proxyIdleConnTimeout,
		})
	requeueDelay := time.Duration(requeueDelaySeconds) * time.Second

	if err := (&controller.KDexInternalHostReconciler{
		Client:              mgr.GetClient(),
		ControllerNamespace: controllerNamespace,
		Configuration:       conf,
		FocalHost:           focalHost,
		HostHandler:         hostHandler,
		Port:                webserverPort(webserverAddr),
		RefreshGraceWindow:  refreshGraceWindow,
		RequeueDelay:        requeueDelay,
		Scheme:              mgr.GetScheme(),
		ServiceName:         serviceName,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KDexInternalHost")
		os.Exit(1)
	}
	if err := (&controller.KDexInternalPackageReferencesReconciler{
		Client:              mgr.GetClient(),
		Configuration:       conf,
		ControllerNamespace: controllerNamespace,
		FocalHost:           focalHost,
		RequeueDelay:        requeueDelay,
		Scheme:              mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KDexInternalPackageReferences")
		os.Exit(1)
	}
	if err := (&controller.KDexInternalTranslationReconciler{
		Client:              mgr.GetClient(),
		ControllerNamespace: controllerNamespace,
		FocalHost:           focalHost,
		HostHandler:         hostHandler,
		RequeueDelay:        requeueDelay,
		Scheme:              mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KDexInternalTranslation")
		os.Exit(1)
	}
	if err := (&controller.KDexInternalUtilityPageReconciler{
		Client:              mgr.GetClient(),
		Configuration:       conf,
		ControllerNamespace: controllerNamespace,
		FocalHost:           focalHost,
		HostHandler:         hostHandler,
		RequeueDelay:        requeueDelay,
		Scheme:              mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KDexInternalUtilityPage")
		os.Exit(1)
	}
	if err := (&controller.KDexPageReconciler{
		Client:              mgr.GetClient(),
		Configuration:       conf,
		ControllerNamespace: controllerNamespace,
		FocalHost:           focalHost,
		HostHandler:         hostHandler,
		RequeueDelay:        requeueDelay,
		Scheme:              mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KDexPage")
		os.Exit(1)
	}
	// FUNCTION_IMAGE_PREFIX overrides the function-image path segment before
	// <func> (default: HostRef.Name+"/"). LookupEnv distinguishes unset
	// (nil -> host-name default) from set-empty ("" -> flat path).
	var functionImagePrefix *string
	if v, ok := os.LookupEnv("FUNCTION_IMAGE_PREFIX"); ok {
		functionImagePrefix = &v
	}
	if err := (&controller.KDexFunctionReconciler{
		Client:              mgr.GetClient(),
		Configuration:       conf,
		ControllerNamespace: controllerNamespace,
		FocalHost:           focalHost,
		FunctionImagePrefix: functionImagePrefix,
		HostHandler:         hostHandler,
		RequeueDelay:        requeueDelay,
		Scheme:              mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KDexFunction")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	if pprofAddr != "" && strings.Contains(pprofAddr, ":") {
		setupLog.Info("starting pprof server", "address", pprofAddr)
		go func() {
			runtime.SetBlockProfileRate(1)
			log.Println(http.ListenAndServe(pprofAddr, nil))
		}()
	}

	ctx := ctrl.SetupSignalHandler()

	srv, appliedTimeouts := server.New(webserverAddr, hostHandler, server.Timeouts{
		ReadHeaderTimeout:  serverReadHeaderTimeout,
		ReadTimeout:        serverReadTimeout,
		WriteTimeout:       serverWriteTimeout,
		IdleTimeout:        serverIdleTimeout,
		StreamStallTimeout: serverStreamStallTimeout,
	})

	// Report an applied stall window that differs from what the operator
	// wrote. Clamped rather than rejected for the same reason
	// --refresh-grace-window is (see internal/auth/exchange.go): this
	// process is the site's serving path. Logged loudly because a running
	// config that silently disagrees with the flags is exactly what makes
	// the inversion hard to find. See kdex-tech/host-manager#173.
	if appliedTimeouts.StreamStallTimeout != serverStreamStallTimeout {
		setupLog.Info(
			"--server-stream-stall-timeout was below --server-write-timeout and has been clamped up to it; "+
				"the stall window is the SSE-specific sliding deadline and is meant to be the LARGER of the two, "+
				"so a lower value made text/event-stream responses more fragile than ordinary chunked responses",
			"requested", serverStreamStallTimeout.String(),
			"applied", appliedTimeouts.StreamStallTimeout.String(),
			"server-write-timeout", serverWriteTimeout.String())
	}

	go func() {
		setupLog.Info("starting web server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			setupLog.Error(err, "problem running web server")
		}
	}()

	go func() {
		<-ctx.Done()
		setupLog.Info("shutting down web server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			setupLog.Error(err, "problem shutting down web server")
		}
	}()

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func loadLogLevelsFromEnv(namedLogLevelPairs *kdexlog.NamedLogLevelPairs) error {
	blob := os.Getenv("NAMED_LOG_LEVELS")

	for part := range strings.FieldsSeq(blob) {
		if err := namedLogLevelPairs.Set(part); err != nil {
			return err
		}
	}

	return nil
}

func webserverPort(address string) int32 {
	idx := strings.LastIndexAny(address, ":")

	if idx == -1 {
		return 80
	}

	i, err := strconv.ParseInt(address[idx+1:], 10, 32)

	if err != nil {
		panic(err)
	}

	return int32(i)
}
