package host

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

type errorResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	statusMsg   string
	wroteHeader bool
}

var _ http.ResponseWriter = (*errorResponseWriter)(nil)

// Flush implements the http.Flusher interface.
func (ew *errorResponseWriter) Flush() {
	// If we have an error code, we don't want to flush the
	// "bad" body yet, as the middleware will handle it.
	if ew.statusCode >= 400 {
		return
	}

	// Pass the flush signal to the underlying ResponseWriter
	if flusher, ok := ew.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack lets the caller take over the connection (needed for WebSockets)
func (ew *errorResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := ew.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support Hijacker")
}

// Push implements HTTP/2 server push
func (ew *errorResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := ew.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (ew *errorResponseWriter) Write(b []byte) (int, error) {
	if ew.statusCode >= 400 {
		// Drop original error body, we will render our own
		ew.statusMsg += string(b)
		return len(b), nil
	}
	if !ew.wroteHeader {
		ew.WriteHeader(http.StatusOK)
	}
	return ew.ResponseWriter.Write(b)
}

func (ew *errorResponseWriter) WriteHeader(code int) {
	if ew.wroteHeader {
		return
	}
	// An informational 1xx does NOT complete the response: more headers,
	// and the real final status, are still to come. Delegate it and return
	// without latching wroteHeader or recording statusCode -- doing either
	// swallowed the final WriteHeader, so a backend emitting 103 Early
	// Hints before a 500 never set statusCode >= 400, bypassed the
	// error-page path, and reached the client as an implicit 200. It also
	// left statusCode at 103 for feedback.go's unwrap path, which writes it
	// as the final status. See kdex-tech/host-manager#170.
	if code < 200 {
		ew.ResponseWriter.WriteHeader(code)
		return
	}
	ew.statusCode = code
	if code >= 400 {
		return
	}
	ew.wroteHeader = true
	ew.ResponseWriter.WriteHeader(code)
}

type wrappedWriter struct {
	*errorResponseWriter
	f http.Flusher
	h http.Hijacker
	p http.Pusher
}

func (w *wrappedWriter) Flush() {
	w.errorResponseWriter.Flush()
}

func (w *wrappedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.errorResponseWriter.Hijack()
}

func (w *wrappedWriter) Push(target string, opts *http.PushOptions) error {
	return w.errorResponseWriter.Push(target, opts)
}

func GetErrorResponseWriter(w http.ResponseWriter) *errorResponseWriter {
	if ew, ok := w.(*errorResponseWriter); ok {
		return ew
	}
	if wrapped, ok := w.(*wrappedWriter); ok {
		return wrapped.errorResponseWriter
	}
	return nil
}

func wrappedErrorResponseWriter(ew *errorResponseWriter, w http.ResponseWriter) http.ResponseWriter {
	// Check what the original writer supports
	f, _ := w.(http.Flusher)
	h, _ := w.(http.Hijacker)
	p, _ := w.(http.Pusher)

	return &wrappedWriter{ew, f, h, p}
}
