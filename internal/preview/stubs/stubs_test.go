package stubs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotImplementedHandler_ReturnsHelpfulMessage(t *testing.T) {
	h := NotImplemented("login")
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/-/login", nil)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("Code: got %d, want %d", w.Code, http.StatusNotImplemented)
	}
	body := w.Body.String()
	if !strings.Contains(body, "preview") || !strings.Contains(body, "login") {
		t.Errorf("body should mention preview + feature; got: %q", body)
	}
}
