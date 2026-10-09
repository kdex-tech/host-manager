package auth

import (
	"net/url"
	"slices"
	"strings"
)

// authorizeRequest is the part of an /-/oauth/authorize request the consent
// step reasons about. Authorize and the consent POST both derive it from the
// query with parseAuthorizeRequest, so they cannot disagree about what was
// asked for.
type authorizeRequest struct {
	ClientID    string
	RedirectURI string
	State       string
	LoginHint   string
	Prompt      []string
	// Scopes are the requested scopes this host supports (what
	// applyScopeFilter would issue), sorted and unique. Anything else is
	// neither shown nor recorded.
	Scopes []string
}

func parseAuthorizeRequest(q url.Values) authorizeRequest {
	return authorizeRequest{
		ClientID:    q.Get("client_id"),
		RedirectURI: q.Get("redirect_uri"),
		State:       q.Get("state"),
		LoginHint:   q.Get("login_hint"),
		Prompt:      strings.Fields(q.Get("prompt")),
		Scopes:      supportedScopes(q.Get("scope")),
	}
}

func supportedScopes(scope string) []string {
	var out []string
	for s := range strings.FieldsSeq(scope) {
		if slices.Contains(SupportedScopes, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// withoutPrompt returns a copy of q with the given prompt values removed, and
// prompt itself removed when nothing is left. The login detour drops
// login/select_account/none (they are satisfied by logging in) and keeps
// consent; the Allow redirect drops consent (it is satisfied by allowing).
// Either way the request cannot loop back into the step it just finished.
func withoutPrompt(q url.Values, drop ...string) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = slices.Clone(v)
	}
	kept := slices.DeleteFunc(strings.Fields(q.Get("prompt")), func(p string) bool {
		return slices.Contains(drop, p)
	})
	if len(kept) == 0 {
		out.Del("prompt")
	} else {
		out.Set("prompt", strings.Join(kept, " "))
	}
	return out
}
