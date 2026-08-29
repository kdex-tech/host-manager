/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import "net/http"

// HeaderPreserver is a http.ResponseWriter that can be told which response
// headers THIS PROCESS authored, so a downstream re-render can restore them
// after wiping everything a proxied backend left behind.
//
// Implemented by internal/host's errorResponseWriter, which buffers every
// >= 400 response and (for an HTML-accepting caller) re-renders it through the
// error utility page. That re-render deletes the whole header map, because a
// suppressed proxy body leaves a Content-Length describing bytes the client
// will never receive. Recording provenance is what lets the wipe stay total
// while a challenge this process wrote still reaches the client.
//
// Declared here rather than in internal/host because internal/host imports
// internal/auth, so the dependency cannot run the other way.
type HeaderPreserver interface {
	PreserveHeader(name, value string)
}

// PreserveHeader sets a response header AND, when w can record provenance,
// marks it as authored by this process so it survives a header wipe.
//
// Use it for any header that describes the REJECTION rather than the body --
// a WWW-Authenticate challenge above all. Never for a header copied from an
// upstream response: a backend's challenge reaching a browser on the host's
// origin is a phishing primitive, not a contract.
func PreserveHeader(w http.ResponseWriter, name, value string) {
	if p, ok := w.(HeaderPreserver); ok {
		p.PreserveHeader(name, value)
		return
	}
	w.Header().Set(name, value)
}
