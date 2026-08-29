package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
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
		req.Header.Set("Accept", "text/html")
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

	// canGenerateSniffer treats an AuthContext with an empty subject the
	// same as no AuthContext at all -- it returns before CheckAccess runs
	// either way (mirrors the guard apitoken.go already applies after a
	// successful GetAuthContext). The header guard must use the identical
	// definition of anonymous, not merely "AuthContext present."
	t.Run("says nothing to a caller with an empty subject", func(t *testing.T) {
		ac := &snifferGateChecker{allow: true}
		hh, ctx := newSnifferTestHandler(t, ac)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		ctx = auth.SetAuthContext(ctx, auth.AuthContext{})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Empty(t, ac.resource, "CheckAccess must not run for a subject-less AuthContext")
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

	// Suppression is reached from TWO arms and only one of them 404s. In the
	// other -- a matched, mutable function carrying X-KDex-* headers -- control
	// falls through to next.ServeHTTP, which can answer 200. A header saying
	// "your missing entitlement suppressed something" riding on a successful
	// response describes nothing that happened to that request.
	t.Run("does not ride the header on the matched-function arm", func(t *testing.T) {
		ac := &snifferGateChecker{allow: false}
		hh, ctx := newSnifferTestHandler(t, ac)

		fn := kdexv1alpha1.KDexFunction{
			Spec: kdexv1alpha1.KDexFunctionSpec{
				API: kdexv1alpha1.API{BasePath: "/v2/mutable"},
			},
		}
		// Mutable: no spec.origin.executable and no spec.origin.source.
		assert.True(t, isMutable(&fn), "fixture must exercise the mutable arm")
		hh.mu.Lock()
		hh.Mux.Handle("/v2/mutable", &KDexFunctionHandler{Function: &fn})
		hh.mu.Unlock()

		nextOK200 := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/v2/mutable", nil)
		// Assigned into the raw map, NOT via Header.Set: DesignMiddleware
		// tests strings.HasPrefix(k, "X-KDex-") against the header key
		// verbatim, and Set/parse canonicalise to "X-Kdex-". The literal
		// spelling is what actually arms this arm.
		req.Header["X-KDex-Function-Name"] = []string{"anything"}
		ctx = auth.SetAuthContext(ctx, auth.AuthContext{"sub": "alice"})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK200).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "the matched function answers normally")
		assert.Empty(t, w.Header().Get("X-KDex-Sniffer-Suppressed"),
			"a suppression header must not ride on a 200")
	})

	// The 404 arm keeps it -- and carries no-store, so an entitlement grant
	// that fixes the suppression is not shadowed by a cached answer.
	t.Run("the 404 arm carries no-store alongside the header", func(t *testing.T) {
		ac := &snifferGateChecker{allow: false}
		hh, ctx := newSnifferTestHandler(t, ac)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		ctx = auth.SetAuthContext(ctx, auth.AuthContext{"sub": "alice"})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "functions:create", w.Header().Get("X-KDex-Sniffer-Suppressed"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
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

// DesignMiddleware deliberately releases hh.mu before the sniffer gate runs,
// so canGenerateSniffer used to read hh.authChecker -- twice -- with no lock
// while SetHost rewrites it. An interface value's itab and data words are
// assigned non-atomically, so a concurrent request could observe
// itab-set/data-nil, clear the `== nil` guard, and nil-deref. This branch
// newly publishes the result of that read to the wire, so the read has to be
// a snapshot. Run under -race.
func TestDesignMiddleware_AuthCheckerReadIsSnapshotted(t *testing.T) {
	hh, ctx := newSnifferTestHandler(t, &snifferGateChecker{allow: false})
	// snifferGateChecker records its arguments into shared fields, which is
	// a race of the TEST's own making. The subject here is hh.authChecker,
	// so use a stateless denier.
	hh.mu.Lock()
	hh.authChecker = statelessDenier{}
	hh.mu.Unlock()

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := hh.DesignMiddleware(next)

	// A writer with SetHost's shape on the one field the gate reads.
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			hh.mu.Lock()
			if i%2 == 0 {
				hh.authChecker = statelessDenier{}
			} else {
				hh.authChecker = nil
			}
			hh.mu.Unlock()
		}
	}()

	reqCtx := auth.SetAuthContext(ctx, auth.AuthContext{"sub": "alice"})
	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 200; j++ {
				req := httptest.NewRequest("GET", "/v2/sniffer", nil).WithContext(reqCtx)
				handler.ServeHTTP(httptest.NewRecorder(), req)
			}
		}()
	}
	readers.Wait()
	close(stop)
	writer.Wait()
}

// statelessDenier is an authChecker with no mutable state, so a test can share
// one across goroutines without introducing a race of its own.
type statelessDenier struct{}

func (statelessDenier) CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return nil, nil
}

func (statelessDenier) CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
	return false, nil
}

func (statelessDenier) GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements {
	return entitlements.ParsedEntitlements{}
}

func (statelessDenier) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return entitlements.ParsedRequirements{}
}

func (statelessDenier) BindRequirements(reqs entitlements.ParsedRequirements, _ entitlements.Binding) (entitlements.ParsedRequirements, error) {
	return reqs, nil
}

func (statelessDenier) VerifyResourceParsedEntitlements(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error) {
	return false, nil
}
