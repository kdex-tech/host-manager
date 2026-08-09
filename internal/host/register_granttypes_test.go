package host

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

// decodeRegisteredGrants pulls grant_types out of a 201 registration response.
func decodeRegisteredGrants(t *testing.T, body []byte) []string {
	t.Helper()
	var got struct {
		GrantTypes []string `json:"grant_types"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode registration response: %v; body=%s", err, body)
	}
	return got.GrantTypes
}

// TestRegisterDropsPasswordGrant closes GHSA-hm9g-w2cw-j7gg.
//
// Dynamic Client Registration is UNAUTHENTICATED and honored a client-supplied
// grant_types array verbatim, while forcing token_endpoint_auth_method to
// "none". An anonymous party could therefore mint a credential-less PUBLIC
// client authorized for the resource-owner password credentials grant, and use
// it to attempt username/password authentication at /-/token.
//
// Not an authentication bypass -- valid credentials are still required -- but
// an unauthenticated, unattributable password-guessing surface: client_ids can
// be rotated freely, which defeats any per-client throttling.
//
// The password grant is removed in OAuth 2.1 and discouraged by RFC 9700 §2.4.
// DCR exists here for zero-touch MCP-client onboarding, and observed MCP
// clients use authorization_code throughout, so restricting DCR-issued clients
// costs that flow nothing.
func TestRegisterDropsPasswordGrant(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})

	rr := postRegister(t, hh, `{"redirect_uris":["http://127.0.0.1:33418/cb"],`+
		`"grant_types":["authorization_code","refresh_token","password"],"client_name":"probe"}`)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	grants := decodeRegisteredGrants(t, rr.Body.Bytes())

	if slices.Contains(grants, "password") {
		t.Fatalf("DCR must not issue a client authorized for the password grant; got %v", grants)
	}
	if !slices.Contains(grants, "authorization_code") {
		t.Fatalf("the supported grants must survive filtering; got %v", grants)
	}
}

// TestRegisterRejectsPasswordOnlyRegistration: filtering a mixed request down
// to the supported set is right, but a request asking ONLY for an unsupported
// grant must not quietly receive a working client for something else. Reject it
// so the caller learns the grant is unavailable.
func TestRegisterRejectsPasswordOnlyRegistration(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})

	rr := postRegister(t, hh, `{"redirect_uris":["http://127.0.0.1:33418/cb"],`+
		`"grant_types":["password"],"client_name":"probe"}`)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	var errBody struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errBody.Error != "invalid_client_metadata" {
		t.Fatalf("error = %q, want invalid_client_metadata", errBody.Error)
	}
}

// TestRegisterDropsClientCredentialsGrant covers the other grant DCR must not
// hand out. A DCR client is forced public (no secret), so a client_credentials
// client minted this way would authenticate with nothing at all.
func TestRegisterDropsClientCredentialsGrant(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})

	rr := postRegister(t, hh, `{"redirect_uris":["http://127.0.0.1:33418/cb"],`+
		`"grant_types":["authorization_code","client_credentials"],"client_name":"probe"}`)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if grants := decodeRegisteredGrants(t, rr.Body.Bytes()); slices.Contains(grants, "client_credentials") {
		t.Fatalf("a forced-public DCR client must not be granted client_credentials; got %v", grants)
	}
}

// TestRegisterPreservesSupportedGrants is the regression guard: the onboarding
// flow DCR exists for must be untouched, both when the client asks explicitly
// and when it omits grant_types entirely.
func TestRegisterPreservesSupportedGrants(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "explicit",
			body: `{"redirect_uris":["http://127.0.0.1:33418/cb"],` +
				`"grant_types":["authorization_code","refresh_token"],"client_name":"probe"}`,
		},
		{
			name: "omitted falls back to the default set",
			body: loopbackBody,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})

			rr := postRegister(t, hh, tc.body)
			if rr.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
			}
			grants := decodeRegisteredGrants(t, rr.Body.Bytes())
			for _, want := range []string{"authorization_code", "refresh_token"} {
				if !slices.Contains(grants, want) {
					t.Fatalf("grant %q must be issued; got %v", want, grants)
				}
			}
		})
	}
}
