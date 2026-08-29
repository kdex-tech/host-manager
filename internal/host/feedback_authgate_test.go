package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/sniffer"
	"github.com/stretchr/testify/assert"
	"kdex.dev/crds/api/v1alpha1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// snifferGateChecker captures the arguments passed to CheckAccess so the test
// can both gate the sniffer and assert on the requested entitlement shape.
type snifferGateChecker struct {
	resource     string
	resourceName string
	requirements []kdexv1alpha1.SecurityRequirement
	verbs        []string
	allow        bool
}

func (m *snifferGateChecker) CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return nil, nil
}

func (m *snifferGateChecker) CheckAccess(_ context.Context, resource, resourceName string, reqs []kdexv1alpha1.SecurityRequirement, verbs ...string) (bool, error) {
	m.resource = resource
	m.resourceName = resourceName
	m.requirements = reqs
	m.verbs = verbs
	return m.allow, nil
}

func (m *snifferGateChecker) GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements {
	return entitlements.ParsedEntitlements{}
}

func (m *snifferGateChecker) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return entitlements.ParsedRequirements{}
}

func (m *snifferGateChecker) BindRequirements(reqs entitlements.ParsedRequirements, _ entitlements.Binding) (entitlements.ParsedRequirements, error) {
	return reqs, nil
}

func (m *snifferGateChecker) VerifyResourceParsedEntitlements(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error) {
	return m.allow, nil
}

func newSnifferTestHandler(t *testing.T, ac *snifferGateChecker) (*HostHandler, context.Context) {
	t.Helper()
	logf.SetLogger(logr.Discard())
	ctx := context.Background()
	ctx = logf.IntoContext(ctx, logf.Log)

	cacheManager, _ := cache.NewCacheManager("", "foo", nil)
	hh := NewHostHandler(nil, "test-host", "default", logf.Log, cacheManager)

	sn := &sniffer.RequestSniffer{
		BasePathRegex: (&kdexv1alpha1.API{}).BasePathRegex(),
		CreateFunc: func(obj client.Object, f controllerutil.MutateFn) (controllerutil.OperationResult, error) {
			return controllerutil.OperationResultNone, nil
		},
		Functions:     func() []kdexv1alpha1.KDexFunction { return nil },
		HostName:      hh.Name,
		ItemPathRegex: (&kdexv1alpha1.API{}).ItemPathRegex(),
		OpenAPIBuilder: func() *openapi.Builder {
			return &openapi.Builder{Contact: &openapi3.Contact{}}
		},
		Namespace:       "",
		ReconcileTime:   time.Now(),
		SecuritySchemes: nil,
	}

	hh.SetHost(ctx, &v1alpha1.KDexHostSpec{
		DefaultLang: "en",
		DevMode:     true,
	}, nil, nil, nil, nil, "", nil, nil, nil, nil, "http", sn, time.Now())

	// Inject the mock auth checker — SetHost only wires one when authConfig is
	// supplied, so we force it here to simulate "auth is configured" for tests.
	if ac != nil {
		hh.authChecker = ac
	}

	return hh, ctx
}

func TestHostHandler_DesignMiddleware_SnifferAuthGate(t *testing.T) {
	nextOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	t.Run("denies anonymous request when auth checker is wired", func(t *testing.T) {
		ac := &snifferGateChecker{allow: true}
		hh, ctx := newSnifferTestHandler(t, ac)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code, "sniffer must not redirect anonymous users")
		assert.Empty(t, w.Header().Get("Location"))
		assert.Empty(t, ac.resource, "CheckAccess must not run for anonymous users")
	})

	t.Run("denies logged-in user without functions:create entitlement", func(t *testing.T) {
		ac := &snifferGateChecker{allow: false}
		hh, ctx := newSnifferTestHandler(t, ac)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		ctx = auth.SetAuthContext(ctx, auth.AuthContext{"sub": "alice"})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code, "users without the entitlement must not trigger sniffer")
		assert.Empty(t, w.Header().Get("Location"))
		assert.Equal(t, "functions", ac.resource)
		assert.Equal(t, "*", ac.resourceName)
		assert.Equal(t, []string{"create"}, ac.verbs)
		if assert.Len(t, ac.requirements, 1) {
			assert.Equal(t, []string{"functions:create"}, ac.requirements[0]["bearer"])
		}
	})

	// The 404 is truthful -- the path does not exist, which is why the
	// sniffer was reached at all. But suppression was visible only at V(1),
	// which is why "I expected a 303, got 404" is a documented question.
	// Name the missing entitlement in a header so curl -i answers it,
	// without relabelling an absence as a denial.
	t.Run("names the missing entitlement in a response header", func(t *testing.T) {
		ac := &snifferGateChecker{allow: false}
		hh, ctx := newSnifferTestHandler(t, ac)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		ctx = auth.SetAuthContext(ctx, auth.AuthContext{"sub": "alice"})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"the path really does not exist; the contract governs denials, not absences")
		assert.Equal(t, "functions:create", w.Header().Get("X-KDex-Sniffer-Suppressed"))
	})

	// An anonymous caller is never told which entitlement they lack: they
	// presented no credential, so the header would advertise the gate rather
	// than explain a decision about them.
	t.Run("says nothing to an anonymous caller", func(t *testing.T) {
		ac := &snifferGateChecker{allow: true}
		hh, ctx := newSnifferTestHandler(t, ac)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Empty(t, w.Header().Get("X-KDex-Sniffer-Suppressed"))
	})

	t.Run("allows logged-in user with functions:create entitlement", func(t *testing.T) {
		ac := &snifferGateChecker{allow: true}
		hh, ctx := newSnifferTestHandler(t, ac)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		ctx = auth.SetAuthContext(ctx, auth.AuthContext{"sub": "alice"})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "/-/sniffer/inspect/")
	})

	t.Run("preserves legacy behavior when no auth checker is wired", func(t *testing.T) {
		hh, ctx := newSnifferTestHandler(t, nil)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "/-/sniffer/inspect/")
	})
}
