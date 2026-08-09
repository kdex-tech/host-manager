package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// recordingWriter captures every WriteHeader code the wrapper delegates, so a
// test can tell "the 1xx was passed through" from "the 1xx became the final
// status".
type recordingWriter struct {
	*httptest.ResponseRecorder
	codes []int
}

func newRecordingWriter() *recordingWriter {
	return &recordingWriter{ResponseRecorder: httptest.NewRecorder()}
}

func (r *recordingWriter) WriteHeader(code int) {
	r.codes = append(r.codes, code)
	// Only the first non-1xx code completes the response, matching the
	// stdlib: httptest.ResponseRecorder would otherwise record a 1xx as
	// Result().StatusCode.
	if code >= 200 {
		r.ResponseRecorder.WriteHeader(code)
	}
}

// TestErrorResponseWriter_EarlyHintsThenError pins kdex-tech/host-manager#170.
//
// WriteHeader latched wroteHeader (and set statusCode) on an informational
// 1xx, so the real, final WriteHeader was swallowed by the wroteHeader guard.
// A backend emitting `103 Early Hints` before a 500 therefore never set
// statusCode >= 400: the error-page path was bypassed entirely and the
// response reached the client as an implicit 200.
//
// 1xx does not complete a response. It must be delegated and forgotten.
func TestErrorResponseWriter_EarlyHintsThenError(t *testing.T) {
	rec := newRecordingWriter()
	ew := &errorResponseWriter{ResponseWriter: rec}

	ew.WriteHeader(http.StatusEarlyHints)
	ew.WriteHeader(http.StatusInternalServerError)

	assert.Equal(t, http.StatusInternalServerError, ew.statusCode,
		"the final status must be observed; a preceding 103 must not latch the writer and hide it")
	assert.Equal(t, []int{http.StatusEarlyHints}, rec.codes,
		"the 103 must be delegated, and a >=400 status must NOT be written through — the error-page path renders it")
}

// TestErrorResponseWriter_EarlyHintsThenSuccess proves the 1xx passthrough
// does not break the ordinary success path: the informational response still
// reaches the client, and the following 200 is what completes the response.
func TestErrorResponseWriter_EarlyHintsThenSuccess(t *testing.T) {
	rec := newRecordingWriter()
	ew := &errorResponseWriter{ResponseWriter: rec}

	ew.WriteHeader(http.StatusEarlyHints)
	ew.WriteHeader(http.StatusOK)

	assert.Equal(t, http.StatusOK, ew.statusCode)
	assert.True(t, ew.wroteHeader, "a final 2xx must latch the writer")
	assert.Equal(t, []int{http.StatusEarlyHints, http.StatusOK}, rec.codes,
		"both the informational and the final status must reach the client, in order")
}

// TestErrorResponseWriter_MultipleEarlyHints covers a backend emitting more
// than one informational response, which RFC 8297 permits.
func TestErrorResponseWriter_MultipleEarlyHints(t *testing.T) {
	rec := newRecordingWriter()
	ew := &errorResponseWriter{ResponseWriter: rec}

	ew.WriteHeader(http.StatusContinue)
	ew.WriteHeader(http.StatusEarlyHints)
	ew.WriteHeader(http.StatusNotFound)

	assert.Equal(t, http.StatusNotFound, ew.statusCode,
		"repeated 1xx responses must still leave the writer able to observe the final status")
	assert.Equal(t, []int{http.StatusContinue, http.StatusEarlyHints}, rec.codes)
}

// TestErrorResponseWriter_NoEarlyHints is the regression guard: the behaviour
// without any 1xx must be untouched by the fix.
func TestErrorResponseWriter_NoEarlyHints(t *testing.T) {
	t.Run("error status is captured, not written through", func(t *testing.T) {
		rec := newRecordingWriter()
		ew := &errorResponseWriter{ResponseWriter: rec}

		ew.WriteHeader(http.StatusBadGateway)

		assert.Equal(t, http.StatusBadGateway, ew.statusCode)
		assert.False(t, ew.wroteHeader, "an error status must not latch; the error page still has to render")
		assert.Empty(t, rec.codes, "an error status must not reach the client directly")
	})

	t.Run("success status is written through and latches", func(t *testing.T) {
		rec := newRecordingWriter()
		ew := &errorResponseWriter{ResponseWriter: rec}

		ew.WriteHeader(http.StatusOK)
		ew.WriteHeader(http.StatusInternalServerError)

		assert.Equal(t, http.StatusOK, ew.statusCode,
			"once a final status is committed, a later WriteHeader must be ignored")
		assert.Equal(t, []int{http.StatusOK}, rec.codes)
	})
}
