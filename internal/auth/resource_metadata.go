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
	"net/url"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// CheckedResourceMetadata returns raw when it may be emitted inside an RFC 9728
// resource_metadata auth-param, and "" when it may not. It is the ONE gate every
// emitter of that parameter goes through: internal/auth/denial.Write (the denial
// contract's 401/403 challenges) and bearerChallenge (the invalid/expired-token
// 401 raised by WithAuthentication).
//
// It lives HERE, in internal/auth, rather than in internal/auth/denial, because
// the dependency only runs one way: internal/auth/denial imports internal/auth,
// so internal/auth cannot import it back. Two emitters, one implementation --
// the alternative was a second copy of the rule in the more reachable of the two
// paths, which is how the two halves came to disagree in the first place.
//
// # Why the value needs checking at all
//
// The value both emitters carry is <issuer> + protectedResourcePath + basePath.
// The issuer half is hostname-validated; basePath is NOT. Its CRD pattern is
// `^/\w+/\w+`, which is START-ANCHORED ONLY, so
// `/a/b",resource_metadata="https://attacker.example/x` is a valid
// spec.api.basePath. Emitting it raw would put a SECOND resource_metadata
// parameter in the challenge and let an RFC 9728 client be steered to an
// attacker-run authorization server. Go rewrites only CR/LF on write, so this
// cannot split a response -- but it fully controls this header's auth-params,
// which is enough.
//
// Anchoring the CRD pattern with `$` and giving it a MaxLength is the upstream
// fix and lives in kdex-crds; this consumer-side check is the defence in depth
// that holds whichever CRD version happens to be installed.
//
// # Omit, never clean
//
// A rejected value yields "", and the CALLER drops the parameter while keeping
// the rest of its challenge. Emitting a sanitized value would hand an RFC 9728
// client a URL nobody authored; omitting the pointer costs it discovery and
// nothing else.
//
// The rejection is logged at V(0): an operator has authored a basePath that
// cannot be expressed in this header, and the only other symptom is an OAuth2/MCP
// client with no discovery pointer. That is worth seeing at the default
// verbosity. An empty raw is the ordinary "this resource is not oauth2-protected"
// case and is not logged.
func CheckedResourceMetadata(ctx context.Context, raw string) string {
	if raw == "" || safeResourceMetadata(raw) {
		return raw
	}
	logf.FromContext(ctx).V(0).Info(
		"rejected resource-metadata URL; omitting resource_metadata from the challenge",
		"resourceMetadata", raw)
	return ""
}

// safeResourceMetadata reports whether raw may be emitted inside the
// resource_metadata auth-param's HTTP quoted-string. Unexported on purpose:
// CheckedResourceMetadata is the only correct way to use it, because the
// omit-and-log policy is half the rule.
func safeResourceMetadata(raw string) bool {
	if raw == "" {
		return false
	}
	for i := 0; i < len(raw); i++ {
		// The quoted-string delimiters, the quoted-pair escape, and anything
		// a header value has no business carrying.
		if c := raw[i]; c == '"' || c == '\\' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	u, err := url.Parse(raw)
	// IsAbs: RFC 9728 names an absolute metadata URL. A relative value would
	// resolve against whatever the client happens to be pointed at.
	return err == nil && u.IsAbs()
}
