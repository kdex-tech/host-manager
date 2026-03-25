package host

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"
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

	hh.apitokenRevokeHandler(rr, req)

	g.Expect(rr.Code).To(Equal(http.StatusNotImplemented))
}
