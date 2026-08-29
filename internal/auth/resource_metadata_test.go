/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"context"
	"strings"
	"testing"
)

func TestSafeResourceMetadata(t *testing.T) {
	valid := []string{
		"https://example.test/.well-known/oauth-protected-resource/api/v1/mcp",
		"http://localhost:8080/.well-known/oauth-protected-resource/a/b",
	}
	for _, v := range valid {
		if !safeResourceMetadata(v) {
			t.Fatalf("safeResourceMetadata(%q) = false, want true", v)
		}
	}
	invalid := map[string]string{
		"empty":         "",
		"quote":         `https://example.test/a"b`,
		"backslash":     `https://example.test/a\b`,
		"newline":       "https://example.test/a\nb",
		"nul":           "https://example.test/a\x00b",
		"del":           "https://example.test/a\x7fb",
		"relative":      "/.well-known/oauth-protected-resource/api/v1/mcp",
		"scheme-less":   "example.test/.well-known/oauth-protected-resource",
		"unparseable":   "https://example.test/%zz",
		"control-vtab":  "https://example.test/a\vb",
		"control-ff":    "https://example.test/a\fb",
		"embedded-crlf": "https://example.test/a\r\nX-Evil: 1",
	}
	for name, v := range invalid {
		if safeResourceMetadata(v) {
			t.Fatalf("safeResourceMetadata(%q) [%s] = true, want false", v, name)
		}
	}
}

// CheckedResourceMetadata omits, it never cleans: a rejected pointer becomes ""
// so the caller drops the parameter, and an accepted one is returned byte-for-byte.
func TestCheckedResourceMetadataOmitsRatherThanCleans(t *testing.T) {
	const good = "https://example.test/.well-known/oauth-protected-resource/api/v1/mcp"
	if got := CheckedResourceMetadata(context.Background(), good); got != good {
		t.Fatalf("CheckedResourceMetadata(good) = %q, want it returned unchanged", got)
	}
	const evil = `https://example.test/.well-known/oauth-protected-resource/a/b",resource_metadata="https://attacker.example/x`
	if got := CheckedResourceMetadata(context.Background(), evil); got != "" {
		t.Fatalf("CheckedResourceMetadata(evil) = %q, want \"\" (omit, never clean)", got)
	}
	// The not-oauth2-protected case: "" in, "" out, nothing to log about.
	if got := CheckedResourceMetadata(context.Background(), ""); got != "" {
		t.Fatalf("CheckedResourceMetadata(\"\") = %q, want \"\"", got)
	}
}

// bearerChallenge emits resource_metadata on the far more reachable of the two
// paths -- every invalid or expired bearer to a protected path, not only a
// policy denial -- and it used to concatenate the operator-supplied URL with no
// validation at all. spec.api.basePath's CRD pattern (`^/\w+/\w+`) is
// start-anchored ONLY, so the quote-bearing basePath below is valid CR data and
// would have given the challenge a SECOND resource_metadata parameter naming an
// attacker-run authorization server.
//
// The pointer goes; error= and error_description= stay. A client that cannot
// discover the AS still learns why its token was rejected.
func TestBearerChallengeDropsQuoteBearingResourceMetadata(t *testing.T) {
	const basePath = `/a/b",resource_metadata="https://attacker.example/x`
	c := &Config{
		OAuth2ResourceMetadata: map[string]string{
			basePath: "https://example.test/.well-known/oauth-protected-resource" + basePath,
		},
	}

	got := c.bearerChallenge(context.Background(), basePath, nil)

	if want := `Bearer error="invalid_token", error_description="the access token is invalid"`; got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
	if strings.Contains(got, "attacker.example") {
		t.Fatalf("challenge = %q; the attacker-controlled pointer reached the header", got)
	}
}

// The same challenge keeps a well-formed pointer: dropping is the exception,
// not the rule, and this is what stops the fix from silently disabling RFC 9728
// discovery for every expired token.
func TestBearerChallengeKeepsSafeResourceMetadata(t *testing.T) {
	const basePath = "/api/v1/mcp"
	const md = "https://example.test/.well-known/oauth-protected-resource/api/v1/mcp"
	c := &Config{OAuth2ResourceMetadata: map[string]string{basePath: md}}

	got := c.bearerChallenge(context.Background(), basePath, nil)

	want := `Bearer error="invalid_token", error_description="the access token is invalid", ` +
		`resource_metadata="` + md + `"`
	if got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}
