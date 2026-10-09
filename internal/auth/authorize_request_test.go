package auth

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSupportedScopesDropsUnknownAndDuplicates(t *testing.T) {
	assert.Equal(t, []string{"email", "openid"}, supportedScopes("openid read-only email openid"))
	assert.Empty(t, supportedScopes(""))
}

func TestWithoutPromptRemovesOnlyTheNamedValues(t *testing.T) {
	q := url.Values{"prompt": {"login consent"}, "state": {"x"}}
	got := withoutPrompt(q, "login", "select_account", "none")
	assert.Equal(t, "consent", got.Get("prompt"))
	assert.Equal(t, "login consent", q.Get("prompt"), "the input is not modified")

	got = withoutPrompt(url.Values{"prompt": {"consent"}}, "consent")
	assert.False(t, got.Has("prompt"), "an emptied prompt is removed entirely")
}

func TestAuthorizeLoginURLKeepsConsent(t *testing.T) {
	r := httptest.NewRequest("GET", "/-/oauth/authorize?prompt=login+consent&login_hint=a%40b.c&state=x", nil)
	loc, _ := url.Parse(authorizeLoginURL(r, []string{"login", "consent"}, "a@b.c"))
	ret, _ := url.Parse(loc.Query().Get("return"))
	assert.Equal(t, "consent", ret.Query().Get("prompt"), "consent survives the login detour")
	assert.Empty(t, ret.Query().Get("login_hint"))
	assert.Equal(t, "login", loc.Query().Get("prompt"), "only login/select_account go on to the provider")
}

func TestParseAuthorizeRequest(t *testing.T) {
	got := parseAuthorizeRequest(url.Values{
		"client_id":    {"c"},
		"redirect_uri": {"https://x/cb"},
		"state":        {"s"},
		"login_hint":   {"a@b.c"},
		"prompt":       {"login  consent"},
		"scope":        {"email bogus openid"},
	})
	assert.Equal(t, authorizeRequest{
		ClientID:    "c",
		RedirectURI: "https://x/cb",
		State:       "s",
		LoginHint:   "a@b.c",
		Prompt:      []string{"login", "consent"},
		Scopes:      []string{"email", "openid"},
	}, got)
}
