package host_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/sniffer"
	"github.com/stretchr/testify/assert"
	"kdex.dev/crds/api/v1alpha1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func TestHostHandler_DesignMiddleware(t *testing.T) {
	logf.SetLogger(logr.Discard())
	ctx := context.Background()
	ctx = logf.IntoContext(ctx, logf.Log)

	cacheManager, _ := cache.NewCacheManager("", "foo", nil)
	hh := host.NewHostHandler(nil, "test-host", "default", logf.Log, cacheManager)

	sniffer := &sniffer.RequestSniffer{
		BasePathRegex: (&kdexv1alpha1.API{}).BasePathRegex(),
		CreateFunc: func(obj client.Object, f controllerutil.MutateFn) (controllerutil.OperationResult, error) {
			return controllerutil.OperationResultNone, nil
		},
		Functions:     func() []kdexv1alpha1.KDexFunction { return nil },
		HostName:      hh.Name,
		ItemPathRegex: (&kdexv1alpha1.API{}).ItemPathRegex(),
		OpenAPIBuilder: func() *openapi.Builder {
			return &openapi.Builder{
				Contact: &openapi3.Contact{},
			}
		},
		Namespace:       "",
		ReconcileTime:   time.Now(),
		SecuritySchemes: nil,
	}

	hh.SetHost(ctx, &v1alpha1.KDexHostSpec{
		DefaultLang: "en",
		DevMode:     true,
	}, nil, nil, nil, nil, "", nil, nil, nil, nil, "http", sniffer, time.Now())

	tests := []struct {
		name       string
		next       http.Handler
		assertions func(t *testing.T, got http.Handler)
	}{
		{
			name: "basic",
			next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
			assertions: func(t *testing.T, got http.Handler) {
				req := httptest.NewRequest("GET", "/v2/sniffer", nil)
				req = req.WithContext(ctx)
				w := httptest.NewRecorder()
				got.ServeHTTP(w, req)
				assert.Equal(t, http.StatusSeeOther, w.Code)
				assert.Contains(t, w.Header().Get("Location"), "/-/sniffer/inspect/")
				assert.Contains(t, w.Body.String(), "➔ API Draft Created. View at:")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hh.DesignMiddleware(tt.next)
			tt.assertions(t, got)
		})
	}
}
