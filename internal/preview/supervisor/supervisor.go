// Package supervisor spawns and lifecycles supervised function children for
// directory-form --fn overrides. Each function gets an ephemeral port,
// auth env vars are deliberately omitted (§4.5 auth handling), and Shutdown
// tears all children down (SIGTERM then SIGKILL).
package supervisor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/kdex-tech/host-manager/internal/preview/resolver"
)

// Options configures a Supervisor.
type Options struct {
	// StartupTimeout is how long to wait for a spawned child to bind its
	// allocated port. Default 30 seconds if zero.
	StartupTimeout time.Duration

	// Stderr is where supervisor messages and child stdout/stderr go.
	// Default os.Stderr if nil.
	Stderr io.Writer
}

// Supervisor manages a set of spawned function children.
type Supervisor struct {
	opts     Options
	mu       sync.Mutex
	children []*child
}

type child struct {
	name string
	url  string
	cmd  *exec.Cmd
	// exit receives the result of cmd.Wait exactly once (buffered, size 1).
	// It is populated by a goroutine started in Spawn and must not be used to
	// call cmd.Wait again — that would race. Shutdown drains this channel
	// instead of calling cmd.Wait itself.
	exit <-chan error
}

// New constructs a Supervisor.
func New(opts Options) *Supervisor {
	if opts.StartupTimeout == 0 {
		opts.StartupTimeout = 30 * time.Second
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	return &Supervisor{opts: opts}
}

// Spawn starts a child for the directory-form override and returns the
// http://localhost:<port> URL after the child binds.
//
// Returns an error if:
//   - the override is not a directory form
//   - the language is not supported
//   - port allocation fails
//   - the child fails to start or bind its port before StartupTimeout
func (s *Supervisor) Spawn(ctx context.Context, ov resolver.FnOverride) (string, error) {
	if ov.Kind != resolver.FnOverrideDir {
		return "", fmt.Errorf("supervisor.Spawn: override %q is not directory-form", ov.Name)
	}

	port, err := allocatePort()
	if err != nil {
		return "", fmt.Errorf("allocate port for %q: %w", ov.Name, err)
	}

	cmd, err := buildCommand(ov, port)
	if err != nil {
		return "", err
	}
	cmd.Dir = ov.Dir
	cmd.Env = []string{
		"PORT=" + fmt.Sprint(port),
		"HOME=" + os.Getenv("HOME"),
		"PATH=" + os.Getenv("PATH"),
		"GOPATH=" + os.Getenv("GOPATH"),
		"GOCACHE=" + os.Getenv("GOCACHE"),
		"GOMODCACHE=" + os.Getenv("GOMODCACHE"),
		// AUDIENCE / ISSUER / JWKS_URL / PKS_URL deliberately omitted.
		// See §4.5 auth handling.
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prefix := fmt.Sprintf("[%s] ", ov.Name)
	cmd.Stdout = prefixWriter{w: s.opts.Stderr, prefix: prefix}
	cmd.Stderr = prefixWriter{w: s.opts.Stderr, prefix: prefix}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start %q: %w", ov.Name, err)
	}

	// exitCh carries the result of cmd.Wait exactly once. It is buffered (size 1)
	// so that the goroutine can send and exit without a receiver. After Spawn
	// returns success (port bound), the channel is stashed on the child struct
	// and drained by Shutdown instead of calling cmd.Wait a second time.
	exitCh := make(chan error, 1)
	go func() {
		exitCh <- cmd.Wait()
	}()

	url := fmt.Sprintf("http://localhost:%d", port)

	if err := waitForPort(ctx, waitForPortArgs{
		url:       url,
		timeout:   s.opts.StartupTimeout,
		childExit: exitCh,
	}); err != nil {
		_ = killTree(cmd)
		return "", fmt.Errorf("function %q failed to bind port %d within %s: %w", ov.Name, port, s.opts.StartupTimeout, err)
	}

	s.mu.Lock()
	s.children = append(s.children, &child{name: ov.Name, url: url, cmd: cmd, exit: exitCh})
	s.mu.Unlock()
	return url, nil
}

// Shutdown sends SIGTERM to every child, waits up to gracePeriod, then SIGKILL.
// It is idempotent — a second call sees an empty children list and returns nil.
func (s *Supervisor) Shutdown(gracePeriod time.Duration) error {
	s.mu.Lock()
	children := s.children
	s.children = nil
	s.mu.Unlock()

	for _, c := range children {
		_, _ = fmt.Fprintf(s.opts.Stderr, "[%s] shutting down\n", c.name)
		_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGTERM)
	}
	done := make(chan struct{})
	go func() {
		// Drain each child's exit channel instead of calling cmd.Wait again
		// (cmd.Wait may only be called once; the goroutine launched in Spawn
		// already owns that call).
		for _, c := range children {
			<-c.exit
		}
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(gracePeriod):
		for _, c := range children {
			_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return nil
	}
}

// buildCommand picks the spawn command per detected language.
func buildCommand(ov resolver.FnOverride, _ int) (*exec.Cmd, error) {
	switch ov.Lang {
	case resolver.FnLangGo:
		return exec.Command("go", "run", "."), nil
	case resolver.FnLangNode:
		return exec.Command("npm", "run", "dev"), nil
	default:
		return nil, fmt.Errorf("unsupported language for %q", ov.Name)
	}
}

// allocatePort binds :0, reads the assigned port, then closes the listener.
// Race window: between close and the child re-binding, another process could
// claim the port. In practice this is rare (ephemeral port ranges are large)
// and documented as a known edge case for v1.
func allocatePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port, nil
}

// waitForPortArgs bundles the arguments for waitForPort.
type waitForPortArgs struct {
	url       string
	timeout   time.Duration
	childExit <-chan error
}

// waitForPort polls the URL until it returns any HTTP response (200, 404, etc.),
// the context is canceled, the timeout elapses, or the child process exits
// prematurely. The last case provides fast failure when the child crashes (e.g.
// compile error, panic) instead of waiting out the full StartupTimeout.
func waitForPort(ctx context.Context, args waitForPortArgs) error {
	deadline := time.Now().Add(args.timeout)
	client := http.Client{Timeout: 500 * time.Millisecond}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-args.childExit:
			// Child died before binding its port. Return the exit error so the
			// caller sees the actual failure (build error, panic, etc.) rather
			// than a generic timeout.
			if err != nil {
				return fmt.Errorf("child exited before binding port: %w", err)
			}
			return fmt.Errorf("child exited before binding port (status 0)")
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout")
			}
			resp, err := client.Get(args.url + "/")
			if err == nil {
				_ = resp.Body.Close()
				return nil
			}
		}
	}
}

// killTree sends SIGKILL to the child's process group.
func killTree(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// prefixWriter prefixes every line written through it with prefix.
//
// Implementation note: bytes.ReplaceAll inserts the prefix after every internal
// newline. If the write does not end with a newline (partial line), the chunk
// is still emitted with its leading prefix; the next Write will also prepend a
// prefix, so a logical line spanning two writes will show two prefix runs. For
// the Phase 2 dev preview this is acceptable — go run flushes by line.
type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (p prefixWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	// Insert the prefix at the start and after every internal newline. If b
	// ends with a newline, an extra prefix is appended that must be trimmed.
	out := make([]byte, 0, len(b)+len(p.prefix))
	out = append(out, p.prefix...)
	out = append(out, bytes.ReplaceAll(b, []byte("\n"), append([]byte("\n"), p.prefix...))...)
	// Trim the trailing prefix that was added after a terminal newline.
	if len(p.prefix) > 0 && bytes.HasSuffix(out, []byte(p.prefix)) {
		out = out[:len(out)-len(p.prefix)]
	}
	if _, err := p.w.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}
