package host

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	. "github.com/onsi/gomega"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestHostHandler_ApitokenRevokeHandler_MethodNotAllowed(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{}

	req := httptest.NewRequest(http.MethodGet, "/-/apitokens/revoke", nil)
	rr := httptest.NewRecorder()

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
}

func TestHostHandler_ApitokenRevokeHandler_NotImplemented(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{}

	reqBody, _ := json.Marshal(RevokeRequest{Token: "some-token"})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// AuthContext for 'test-user'
	ac := auth.AuthContext{"sub": "test-user"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	// Since authConfig is nil, it returns 501
	g.Expect(rr.Code).To(Equal(http.StatusNotImplemented))
}

func TestHostHandler_ApitokenRevokeHandler_Unauthorized(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{}

	reqBody, _ := json.Marshal(RevokeRequest{Token: "some-token"})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// No AuthContext in context
	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusUnauthorized))
}

func TestHostHandler_ApitokenRevokeHandler_NoSubject(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{}

	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", nil)
	rr := httptest.NewRecorder()

	// AuthContext WITHOUT 'sub'
	ac := auth.AuthContext{"foo": "bar"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusUnauthorized))
}

func TestHostHandler_ApitokenRevokeHandler_InvalidJSON(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{}

	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBufferString("invalid json"))
	rr := httptest.NewRecorder()

	// AuthContext for 'test-user'
	ac := auth.AuthContext{"sub": "test-user"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusBadRequest))
}

func TestHostHandler_ApitokenRevokeHandler_Forbidden(t *testing.T) {
	g := NewWithT(t)
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), nil)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
		authChecker: &mockApitokenAuthChecker{
			CheckAccessFn: func(ctx context.Context, s1, s2 string, sr []kdexv1alpha1.SecurityRequirement, s3 ...string) (bool, error) {
				return false, nil // Not authorized
			},
		},
	}

	// Token for 'other-user'
	token, _ := tm.MintStatelessKey("aud", "other-user", "act", "scope", time.Hour)

	reqBody, _ := json.Marshal(RevokeRequest{Token: token})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// AuthContext for 'test-user'
	ac := auth.AuthContext{"sub": "test-user"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusForbidden))
}

func TestHostHandler_ApitokenRevokeHandler_InvalidToken(t *testing.T) {
	g := NewWithT(t)
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), nil)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
	}

	reqBody, _ := json.Marshal(RevokeRequest{Token: "invalid.token.here"})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// AuthContext for 'test-user'
	ac := auth.AuthContext{"sub": "test-user"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusBadRequest))
}

func TestHostHandler_ApitokenRevokeHandler_AuthorizedOwner(t *testing.T) {
	g := NewWithT(t)
	cm, _ := cache.NewCacheManager("", "host", nil)
	c := cm.GetCache("revocation", cache.CacheOptions{})
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), c)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
	}

	// Token for 'test-user'
	token, _ := tm.MintStatelessKey("aud", "test-user", "act", "scope", time.Hour)

	reqBody, _ := json.Marshal(RevokeRequest{Token: token})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// AuthContext for 'test-user'
	ac := auth.AuthContext{"sub": "test-user"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusOK))
}

func TestHostHandler_ApitokenRevokeHandler_AuthorizedAdmin(t *testing.T) {
	g := NewWithT(t)
	cm, _ := cache.NewCacheManager("", "host", nil)
	c := cm.GetCache("revocation", cache.CacheOptions{})
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), c)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
		authChecker: &mockApitokenAuthChecker{
			CheckAccessFn: func(ctx context.Context, s1, s2 string, sr []kdexv1alpha1.SecurityRequirement, s3 ...string) (bool, error) {
				// Admin check
				return true, nil
			},
		},
	}

	// Token for 'other-user'
	token, _ := tm.MintStatelessKey("aud", "other-user", "act", "scope", time.Hour)

	reqBody, _ := json.Marshal(RevokeRequest{Token: token})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// AuthContext for 'admin-user'
	ac := auth.AuthContext{"sub": "admin-user"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusOK))
}

func TestHostHandler_ApitokenRevokeHandler_SuccessToken(t *testing.T) {
	g := NewWithT(t)
	cm, _ := cache.NewCacheManager("", "host", nil)
	c := cm.GetCache("revocation", cache.CacheOptions{})
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), c)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
	}

	// Token for 'test-user'
	token, _ := tm.MintStatelessKey("aud", "test-user", "act", "scope", time.Hour)

	reqBody, _ := json.Marshal(RevokeRequest{Token: token})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// AuthContext for 'test-user'
	ac := auth.AuthContext{"sub": "test-user"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusOK))

	var resp RevokeResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	g.Expect(resp.Status).To(Equal("revoked"))

	// Verify token is now invalid
	_, err := tm.ValidateToken(context.Background(), token, "")
	g.Expect(err).To(HaveOccurred())
}

func TestHostHandler_ApitokenRevokeHandler_SuccessMetadata(t *testing.T) {
	g := NewWithT(t)
	cm, _ := cache.NewCacheManager("", "host", nil)
	c := cm.GetCache("revocation", cache.CacheOptions{})
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), c)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
	}

	// Token for 'test-user'
	token, _ := tm.MintStatelessKey("aud", "test-user", "act", "scope", time.Hour)

	reqBody, _ := json.Marshal(RevokeRequest{
		Audience: "aud",
		Sub:      "test-user",
		Action:   "act",
		TTL:      "invalid", // Test invalid TTL duration fallback
	})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// AuthContext for 'test-user'
	ac := auth.AuthContext{"sub": "test-user"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusOK))

	var resp RevokeResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	g.Expect(resp.Status).To(Equal("revoked"))

	// Verify token is now invalid
	_, err := tm.ValidateToken(context.Background(), token, "")
	g.Expect(err).To(HaveOccurred())
}

func TestHostHandler_ApitokenRevokeHandler_MissingMetadata(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: &apitoken.TokenManager{}},
	}

	reqBody, _ := json.Marshal(RevokeRequest{
		Audience: "aud",
		// Sub missing
		Action: "act",
	})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// AuthContext for 'test-user'
	ac := auth.AuthContext{"sub": "test-user"}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusBadRequest))
}

type mockApitokenAuthChecker struct {
	CalculateRequirementsFn func(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error)
	CheckAccessFn           func(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error)
}

func (m *mockApitokenAuthChecker) CalculateRequirements(s1, s2 string, sr []kdexv1alpha1.SecurityRequirement, s3 ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return m.CalculateRequirementsFn(s1, s2, sr, s3...)
}
func (m *mockApitokenAuthChecker) CheckAccess(ctx context.Context, s1, s2 string, sr []kdexv1alpha1.SecurityRequirement, s3 ...string) (bool, error) {
	return m.CheckAccessFn(ctx, s1, s2, sr, s3...)
}
func (m *mockApitokenAuthChecker) GetParsedEntitlements(ctx context.Context) entitlements.ParsedEntitlements {
	return entitlements.ParsedEntitlements{}
}
func (m *mockApitokenAuthChecker) ParseRequirements(sr []kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return entitlements.ParsedRequirements{}
}
func (m *mockApitokenAuthChecker) VerifyResourceParsedEntitlements(s1, s2 string, pe entitlements.ParsedEntitlements, pr entitlements.ParsedRequirements, s3 ...string) (bool, error) {
	return false, nil
}
