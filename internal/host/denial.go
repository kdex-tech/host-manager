/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"net/http"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
)

// denialOwnedHeaders are the response headers denial.Write emits. They
// describe the REJECTION rather than the body, which is exactly the class
// unwrap's re-render must not destroy -- so writeDenial records each one as
// host-authored after Write has set it.
//
// Kept as a list rather than "whatever changed": the point of the mechanism
// is that provenance is asserted deliberately, and a header this package did
// not choose to publish should not acquire survival by accident.
var denialOwnedHeaders = []string{"WWW-Authenticate", "Cache-Control"}

// writeDenial is denial.Write plus provenance.
//
// unwrap (internal/host/feedback.go) wipes the whole header map before
// re-rendering a >= 400 as HTML, because a suppressed proxy body leaves a
// Content-Length describing bytes the client will never get. The challenge a
// gate just wrote has to survive that wipe -- RFC 7235 makes it mandatory on a
// 401 -- but the header map it sits in is the SAME map ReverseProxy copied the
// upstream response headers into (errorResponseWriter embeds the
// ResponseWriter and does not override Header()). Reading the header back by
// name after the fact therefore cannot tell "the host issued this challenge"
// from "a KDexFunction backend returned one", and a backend answering
// `401 WWW-Authenticate: Basic realm="Sign in"` would make the browser render
// a NATIVE CREDENTIAL PROMPT on the host's origin -- a phishing primitive.
//
// So the challenge is recorded at the moment this process emits it, and unwrap
// restores only what was recorded. Every gate goes through here; nothing calls
// denial.Write directly.
//
// The recording lives on the host side because internal/auth/denial must not
// import internal/host (cycle) -- see auth.HeaderPreserver for the seam.
func writeDenial(w http.ResponseWriter, r *http.Request, o denial.Opts) {
	denial.Write(w, r, o)
	for _, h := range denialOwnedHeaders {
		if v := w.Header().Get(h); v != "" {
			auth.PreserveHeader(w, h, v)
		}
	}
}
