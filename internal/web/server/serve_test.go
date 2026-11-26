package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func listen(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return ln, "http://" + ln.Addr().String()
}

func get(url string) (int, error) {
	c := &http.Client{Timeout: time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// After the stop signal the server keeps answering for the drain window, then
// closes its listener: a rollout's old pod serves until the load balancer has
// stopped routing to it, instead of dropping requests on SIGTERM.
func TestServe_KeepsServingThroughTheDrainThenStops(t *testing.T) {
	ln, url := listen(t)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}), ReadHeaderTimeout: time.Second}
	ctx, stop := context.WithCancel(context.Background())
	done := Serve(ctx, srv, ln, 300*time.Millisecond, time.Second, logr.Discard())

	code, err := get(url)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)

	stop()
	time.Sleep(100 * time.Millisecond) // inside the drain window
	code, err = get(url)
	require.NoError(t, err, "a request during the drain must still be served")
	assert.Equal(t, http.StatusOK, code)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop after the drain")
	}
	_, err = get(url)
	assert.Error(t, err, "after the drain the listener is closed")
}

// An in-flight request at shutdown time completes: Shutdown is graceful.
func TestServe_ShutdownLetsAnInFlightRequestFinish(t *testing.T) {
	ln, url := listen(t)
	started := make(chan struct{})
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusTeapot)
	})}
	ctx, stop := context.WithCancel(context.Background())
	done := Serve(ctx, srv, ln, 0, 2*time.Second, logr.Discard())

	result := make(chan int, 1)
	go func() {
		code, _ := get(url)
		result <- code
	}()
	<-started
	stop()

	assert.Equal(t, http.StatusTeapot, <-result)
	<-done
}

// A zero drain shuts down at once, the pre-drain behaviour.
func TestServe_ZeroDrainStopsAtOnce(t *testing.T) {
	ln, _ := listen(t)
	srv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
	ctx, stop := context.WithCancel(context.Background())
	done := Serve(ctx, srv, ln, 0, time.Second, logr.Discard())
	stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a zero drain must stop at once")
	}
}
