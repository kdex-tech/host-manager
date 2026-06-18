/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import "testing"

// TestLooksLikePAT pins the PASETO-vs-JWT credential discrimination used by the
// Bearer auth path: a bare "v4.public." PASETO and a brand-prefixed PAT must be
// recognized as PATs (so the JWT middleware passes them through anonymously),
// while a JWT (three dot-separated base64 segments, header starting "eyJ") must
// NOT be mistaken for a PAT.
func TestLooksLikePAT(t *testing.T) {
	if !looksLikePAT("v4.public.abcDEF", "") {
		t.Fatal("bare PASETO must be detected")
	}
	if !looksLikePAT("kd_d_abcDEF", "kd_d_") {
		t.Fatal("prefixed PAT must be detected")
	}
	if looksLikePAT("eyJhbGc.eyJzdWI.sig", "") {
		t.Fatal("JWT must NOT be detected as PAT")
	}
	// A brand prefix is configured but the credential is a JWT: still not a PAT.
	if looksLikePAT("eyJhbGc.eyJzdWI.sig", "kd_d_") {
		t.Fatal("JWT must NOT be detected as PAT even when a prefix is configured")
	}
	// Exported wrapper must agree with the unexported detector.
	if LooksLikePAT("v4.public.abc", "") != looksLikePAT("v4.public.abc", "") {
		t.Fatal("LooksLikePAT wrapper must mirror looksLikePAT")
	}
}
