package http

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/text/language"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Method string

const (
	Connect Method = http.MethodConnect
	Delete  Method = http.MethodDelete
	Get     Method = http.MethodGet
	Head    Method = http.MethodHead
	Options Method = http.MethodOptions
	Patch   Method = http.MethodPatch
	Post    Method = http.MethodPost
	Put     Method = http.MethodPut
	Trace   Method = http.MethodTrace
)

func DiscoverPattern(patterns []string, r *http.Request) (string, error) {
	mux := http.NewServeMux()
	for _, pattern := range patterns {
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("invalid pattern path %q: %v", pattern, r)
				}
			}()

			mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {})
			return nil
		}()

		if err != nil {
			return "", err
		}
	}

	_, matched := mux.Handler(r)
	if matched == "" {
		return "", fmt.Errorf("request %s %s does not align with any of the pattern paths", r.Method, r.URL.Path)
	}

	return matched, nil
}

func GetLang(r *http.Request, defaultLanguage string, languages []language.Tag) (language.Tag, error) {
	log := logf.FromContext(r.Context())

	if len(languages) == 0 {
		return language.Und, errors.New("no supported languages provided")
	}

	l10n := GetParam("l10n", "", r)

	matcher := language.NewMatcher(languages)

	if l10n != "" {
		tag, err := language.Parse(l10n)
		if err != nil {
			return language.Und, fmt.Errorf("invalid language tag: %s", l10n)
		}

		_, index, confidence := matcher.Match(tag)
		if confidence == language.No {
			return language.Und, fmt.Errorf("language not supported: %s", l10n)
		}

		return languages[index], nil
	}

	preferredLanguages := []language.Tag{}

	for acceptLanguage := range strings.SplitSeq(r.Header.Get("Accept-Language"), ",") {
		acceptLanguage = strings.TrimSpace(acceptLanguage)
		if acceptLanguage == "" {
			continue
		}
		prefix := strings.SplitN(acceptLanguage, ";", 2)[0]
		tag, err := language.Parse(prefix)
		if err != nil {
			log.V(1).Info("failed to parse accept-language header part, skipping", "part", acceptLanguage, "err", err)
			continue
		}
		preferredLanguages = append(preferredLanguages, tag)
	}

	_, index, _ := matcher.Match(preferredLanguages...)

	matchedTag := languages[index]

	if matchedTag.IsRoot() {
		// If we matched root but languages has something else, this might be a fallback.
		// If defaultLanguage is set, we return it.
		if defaultLanguage != "" {
			return language.Parse(defaultLanguage)
		}
		return language.Und, errors.New("no supported language found")
	}

	return matchedTag, nil
}

// SafeReturnPath returns p if it is safe to use as a same-origin redirect
// target, otherwise "/". Anything that a browser would resolve to a different
// origin (absolute URLs, scheme-relative "//evil.com" forms, backslash
// variants used to evade naive prefix checks, non-http schemes) collapses to
// "/". This is the guard for ?return=… / state= values that get fed into
// http.Redirect.
func SafeReturnPath(p string) string {
	if p == "" {
		return "/"
	}
	// Must start with a single forward slash. Reject leading whitespace,
	// backslashes, schemes, and anything else that browsers might resolve
	// to a different origin.
	if !strings.HasPrefix(p, "/") {
		return "/"
	}
	// Reject scheme-relative URLs and backslash variants. Browsers treat "\"
	// like "/" in the authority component, so "/\evil.com" resolves to
	// "//evil.com" → "https://evil.com".
	if strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	// Reject anything url.Parse considers absolute or carrying a host/scheme.
	u, err := url.Parse(p)
	if err != nil || u.IsAbs() || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return p
}

// IsSecure reports whether the request reached us over HTTPS. It returns true
// when the request hit Go's TLS terminator directly, or when a trusted proxy
// signals it via X-Forwarded-Proto. Use this — not r.URL.Scheme — when
// deciding whether to set the Secure attribute on outgoing cookies, because
// r.URL.Scheme is empty for server-received requests.
func IsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		return false
	}
	// Multi-hop proxies append: "https, http" — the first entry is the
	// original client connection.
	first, _, _ := strings.Cut(proto, ",")
	return strings.EqualFold(strings.TrimSpace(first), "https")
}

func GetParam(name string, defaultValue string, r *http.Request) string {
	value := r.PathValue(name)

	if value == "" {
		value = r.URL.Query().Get(name)
	}

	if value == "" {
		return defaultValue
	} else {
		return value
	}
}

func GetParamArray(name string, defaultValue []string, r *http.Request) []string {
	value := r.PathValue(name)
	var values []string

	if value == "" {
		values = r.URL.Query()[name]
	} else {
		values = []string{value}
	}

	if len(values) == 0 {
		return defaultValue
	} else {
		return values
	}
}

func MethodFromString(method string) Method {
	switch method {
	case string(Connect):
		return Connect
	case string(Delete):
		return Delete
	case string(Get):
		return Get
	case string(Head):
		return Head
	case string(Options):
		return Options
	case string(Patch):
		return Patch
	case string(Post):
		return Post
	case string(Put):
		return Put
	case string(Trace):
		return Trace
	default:
		return Get
	}
}

func Methods() []Method {
	return []Method{
		Connect,
		Delete,
		Get,
		Head,
		Options,
		Patch,
		Post,
		Put,
		Trace,
	}
}

func ValidatePattern(pattern string, r *http.Request) (err error) {
	// http.NewServeMux().HandleFunc panics if the pattern is invalid.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid pattern path %q: %v", pattern, r)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {})
	_, matched := mux.Handler(r)
	if matched == "" {
		return fmt.Errorf("request %s %s does not align with pattern path %q", r.Method, r.URL.Path, pattern)
	}

	return nil
}
