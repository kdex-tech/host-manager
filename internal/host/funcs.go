package host

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	openapi "github.com/getkin/kin-openapi/openapi3"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func (hh *HostHandler) convertRequirements(in *[]kdexv1alpha1.SecurityRequirement) *openapi.SecurityRequirements {
	var out *openapi.SecurityRequirements

	if in == nil {
		return out
	}

	out = &openapi.SecurityRequirements{}

	for _, rIn := range *in {
		rNew := openapi.SecurityRequirement{}
		maps.Copy(rNew, rIn)
		out.With(rNew)
	}

	return out
}

func (hh *HostHandler) applyCachingHeaders(
	w http.ResponseWriter,
	r *http.Request,
	requirements []kdexv1alpha1.SecurityRequirement,
	lastModified time.Time,
) bool {
	if !hh.authConfig.IsAuthEnabled() {
		// If auth is disabled, everything is public
		requirements = []kdexv1alpha1.SecurityRequirement{}
	}

	isPrivate := len(requirements) > 0

	if isPrivate {
		w.Header().Set("Cache-Control", "private, no-cache, must-revalidate")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
	}

	vary := "Accept-Language"
	if isPrivate && hh.authConfig.IsAuthEnabled() {
		vary += ", Authorization, Cookie"
	}
	w.Header().Set("Vary", vary)

	identity := ""
	if isPrivate && hh.authConfig.IsAuthEnabled() {
		identity = ":" + hh.getUserHash(r)
	}

	if lastModified.IsZero() {
		lastModified = hh.reconcileTime
	}
	lastModified = lastModified.UTC().Truncate(time.Second)
	etag := fmt.Sprintf(`"%d%s"`, lastModified.Unix(), identity)

	w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
	w.Header().Set("ETag", etag)

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return true
	}

	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		t, err := http.ParseTime(ifModifiedSince)
		if err == nil && !lastModified.After(t) {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}

	return false
}

func (hh *HostHandler) getUserHash(r *http.Request) string {
	// Try Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		h := sha256.Sum256([]byte(auth))
		return hex.EncodeToString(h[:8])
	}
	// Try Cookie
	if hh.authConfig != nil && hh.authConfig.CookieName != "" {
		if cookie, err := r.Cookie(hh.authConfig.CookieName); err == nil {
			h := sha256.Sum256([]byte(cookie.Value))
			return hex.EncodeToString(h[:8])
		}
	}
	return "anon"
}

func (hh *HostHandler) handleAuth(

	r *http.Request,
	w http.ResponseWriter,
	resource string,
	resourceName string,
	requirements []kdexv1alpha1.SecurityRequirement,
) bool {
	if !hh.authConfig.IsAuthEnabled() {
		return false
	}

	authorized, err := hh.authChecker.CheckAccess(
		r.Context(), resource, resourceName, requirements)

	if err != nil {
		hh.log.Error(err, "authorization check failed", resource, resourceName)
		http.Error(w, http.StatusText(http.StatusNotFound)+" "+r.URL.Path, http.StatusNotFound)
		return true
	}

	if !authorized {
		hh.log.V(1).Info("unauthorized access attempt", resource, resourceName)
		http.Error(w, http.StatusText(http.StatusNotFound)+" "+r.URL.Path, http.StatusNotFound)
		return true
	}

	return false
}

// Helper to strip the Domain attribute from a Set-Cookie string
func (hh *HostHandler) stripCookieDomain(cookieStr string) string {
	parts := strings.Split(cookieStr, ";")
	var newParts []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(trimmed), "domain=") {
			newParts = append(newParts, part)
		}
	}
	return strings.Join(newParts, ";")
}

func filterFromQuery(queryParams url.Values) ko.Filter {
	filter := ko.Filter{}

	pathParams := queryParams["path"]
	if len(pathParams) > 0 {
		filter.Paths = pathParams
	}

	tagParams := queryParams["tag"]
	if len(tagParams) > 0 {
		filter.Tags = tagParams
	}

	typeParams := queryParams["type"]
	if len(typeParams) > 0 {
		for _, t := range typeParams {
			switch strings.ToUpper(t) {
			case string(ko.BackendPathType):
				filter.Type = append(filter.Type, ko.BackendPathType)
			case string(ko.FunctionPathType):
				filter.Type = append(filter.Type, ko.FunctionPathType)
			case string(ko.PagePathType):
				filter.Type = append(filter.Type, ko.PagePathType)
			case string(ko.SystemPathType):
				filter.Type = append(filter.Type, ko.SystemPathType)
			}
		}
	}

	return filter
}
