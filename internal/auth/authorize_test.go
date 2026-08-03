package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth/idtoken"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	G "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func TestHostHandler_AuthorizeHandler(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    map[string]string
		cookie         *http.Cookie
		clients        map[string]AuthClient
		expectedStatus int
		expectedLoc    string // Substring check for Location header
	}{
		{
			name:           "missing client_id",
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "unsupported response_type",
			queryParams: map[string]string{
				"client_id":     "client-1",
				"response_type": "token",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid client_id",
			queryParams: map[string]string{
				"client_id":     "unknown-client",
				"response_type": "code",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "not logged in (no cookie)",
			queryParams: map[string]string{
				"client_id":     "client-1",
				"response_type": "code",
				"redirect_uri":  "http://localhost/cb",
			},
			clients: map[string]AuthClient{
				"client-1": {
					ClientID:     "test-client",
					ClientSecret: "test-secret",
					RedirectURIs: []string{"http://localhost/cb"},
				},
			},
			expectedStatus: http.StatusSeeOther,
			expectedLoc:    "/-/login?return=",
		},
		{
			name: "logged in success",
			queryParams: map[string]string{
				"client_id":     "client-1",
				"response_type": "code",
				"redirect_uri":  "http://localhost/cb",
				"state":         "xyz",
			},
			clients: map[string]AuthClient{
				"client-1": {
					ClientID:     "test-client",
					ClientSecret: "test-secret",
					RedirectURIs: []string{"http://localhost/cb"},
				},
			},
			cookie: &http.Cookie{
				Name:  "kdex-auth",
				Value: "dummy-token", // In a real test we need a valid token signature or mock
			},
			expectedStatus: http.StatusFound,
			expectedLoc:    "http://localhost/cb?code=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := G.NewGomegaWithT(t)

			// Generate dummy key for signer
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			g.Expect(err).NotTo(G.HaveOccurred())

			var signerInterface crypto.Signer = privateKey

			// Setup dependencies
			// We need a real Exchanger for IsClientValid
			// But for cookie verification, AuthorizeHandler uses helper or middleware.
			// Current implementation creates a dummy Exchanger with configured Clients

			cfg := &Config{
				Clients: tt.clients,
				OIDC: struct {
					BlockKey     string
					ClientID     string
					ClientSecret string
					IDTokenStore idtoken.IDTokenStore
					Name         string
					ProviderURL  string
					RedirectURL  string
					Scopes       []string
				}{
					BlockKey: "01234567890123456789012345678901", // 32 bytes
				},
				CookieName: "kdex-auth",
				ActivePair: &keys.KeyPair{
					ActiveKey: true,
					KeyId:     "test-kid",
					Private:   privateKey,
				},
			}
			signer, err := sign.NewSigner(
				"test-audience",
				time.Hour,
				"test-issuer",
				&signerInterface,
				"test-kid",
				nil,
			)
			g.Expect(err).NotTo(G.HaveOccurred())
			cfg.Signer = *signer

			exchanger, err := NewExchanger(context.Background(), *cfg, nil, nil)
			g.Expect(err).NotTo(G.HaveOccurred())

			o := &OAuth2{
				AuthConfig:    cfg,
				AuthExchanger: exchanger,
			}

			// Prepare request
			u, _ := url.Parse("/-/oauth/authorize")
			q := u.Query()
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			u.RawQuery = q.Encode()

			req := httptest.NewRequest("GET", u.String(), nil)

			// Inject AuthContext if "logged in"
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
				// We must manually inject the context because middleware is not running here
				// Current AuthorizeHandler impl checks context first, then cookie fallback.
				// Let's inject context to simulate middleware success.
				ctx := req.Context()
				authCtx := AuthContext(jwt.MapClaims{
					"sub": "user-1",
				})
				ctx = SetAuthContext(ctx, authCtx)
				req = req.WithContext(ctx)
			}

			w := httptest.NewRecorder()

			o.AuthorizeHandler(w, req)

			resp := w.Result()
			g.Expect(resp.StatusCode).To(G.Equal(tt.expectedStatus))

			if tt.expectedLoc != "" {
				loc, err := resp.Location()
				g.Expect(err).NotTo(G.HaveOccurred())
				g.Expect(loc.String()).To(G.ContainSubstring(tt.expectedLoc))

				if tt.name == "logged in success" {
					// Verify code presence
					g.Expect(loc.Query().Get("code")).NotTo(G.BeEmpty())
					g.Expect(loc.Query().Get("state")).To(G.Equal("xyz"))
				}
			}
		})
	}
}

// TestAuthorizeHandler_DoesNotLogAuthorizationCode is a regression guard for the
// #11 leak: AuthorizeHandler used to log the full callback URL, which embeds the
// freshly issued authorization code and the state in its query string. It captures
// everything the handler logs and asserts the live code, the state, the callback_url
// field, and the full redirect URL never appear.
func TestAuthorizeHandler_DoesNotLogAuthorizationCode(t *testing.T) {
	g := G.NewGomegaWithT(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	g.Expect(err).NotTo(G.HaveOccurred())
	var signerInterface crypto.Signer = privateKey

	cfg := &Config{
		Clients: map[string]AuthClient{
			"client-1": {
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				RedirectURIs: []string{"http://localhost/cb"},
			},
		},
		OIDC: struct {
			BlockKey     string
			ClientID     string
			ClientSecret string
			IDTokenStore idtoken.IDTokenStore
			Name         string
			ProviderURL  string
			RedirectURL  string
			Scopes       []string
		}{
			BlockKey: "01234567890123456789012345678901", // 32 bytes
		},
		CookieName: "kdex-auth",
		ActivePair: &keys.KeyPair{
			ActiveKey: true,
			KeyId:     "test-kid",
			Private:   privateKey,
		},
	}
	signer, err := sign.NewSigner("test-audience", time.Hour, "test-issuer", &signerInterface, "test-kid", nil)
	g.Expect(err).NotTo(G.HaveOccurred())
	cfg.Signer = *signer

	exchanger, err := NewExchanger(context.Background(), *cfg, nil, nil)
	g.Expect(err).NotTo(G.HaveOccurred())

	o := &OAuth2{AuthConfig: cfg, AuthExchanger: exchanger}

	const stateVal = "csrf-state-sentinel"

	// Logged-in authorize request -> a real code is minted and the handler logs.
	u, _ := url.Parse("/-/oauth/authorize")
	q := u.Query()
	q.Set("client_id", "client-1")
	q.Set("response_type", "code")
	q.Set("redirect_uri", "http://localhost/cb")
	q.Set("state", stateVal)
	u.RawQuery = q.Encode()
	req := httptest.NewRequest("GET", u.String(), nil)

	// Capture everything the handler logs (Verbosity 2 enables the V(1) event).
	var logBuf strings.Builder
	logger := funcr.New(func(prefix, args string) {
		logBuf.WriteString(args)
		logBuf.WriteString("\n")
	}, funcr.Options{Verbosity: 2})

	ctx := logf.IntoContext(req.Context(), logger)
	ctx = SetAuthContext(ctx, AuthContext(jwt.MapClaims{"sub": "user-1"}))
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	o.AuthorizeHandler(w, req)

	resp := w.Result()
	g.Expect(resp.StatusCode).To(G.Equal(http.StatusFound))

	loc, err := resp.Location()
	g.Expect(err).NotTo(G.HaveOccurred())
	code := loc.Query().Get("code")
	g.Expect(code).NotTo(G.BeEmpty(), "a real authorization code should have been minted")

	logged := logBuf.String()
	// Sanity: the handler DID log the authorize event (else the assertions below
	// would pass vacuously).
	g.Expect(logged).To(G.ContainSubstring("OAuth2 authorization"))
	// The actual guard: no live secret / CSRF token / secret-bearing URL in logs.
	g.Expect(logged).NotTo(G.ContainSubstring(code), "authorization code must never be logged")
	g.Expect(logged).NotTo(G.ContainSubstring(stateVal), "state must never be logged")
	g.Expect(logged).NotTo(G.ContainSubstring("callback_url"), "the callback URL field re-leaks code+state")
	g.Expect(logged).NotTo(G.ContainSubstring(loc.String()), "the full redirect URL embeds code+state")
}

// Mock client required for NewHostHandler if we used it, but we constructed manually.
type mockClient struct {
	client.Client
}
