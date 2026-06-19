package host

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Abuse guardrails for the anonymous, write-bearing RFC 7591
// /-/oauth/register endpoint.
//
// Threat model: the endpoint is unauthenticated and creates persisted
// clients. host-manager sits behind a gateway (Traefik/GKE), so the
// inbound X-Forwarded-For header is attacker-controlled (see
// proxy_header_leak_test.go / issue #90). A purely per-IP rate limit
// keyed on XFF is therefore trivially bypassable by IP rotation.
//
// Consequences for the design:
//   - The RELIABLE guard is a single PROCESS-GLOBAL token-bucket limiter
//     on the endpoint. It does not depend on any client-supplied value, so
//     it cannot be evaded by header spoofing or IP rotation. This is the
//     real cap on registration throughput.
//   - The per-IP limiter is BEST-EFFORT defense-in-depth only: it slows a
//     single honest/naive source but is not relied upon for security.

// Endpoint-wide registration limiter defaults.
//
// These are intentionally small, conservative constants rather than
// config knobs; wiring them to DCRConfig can be a follow-up. The global
// limiter is what actually bounds growth of the (anonymous) client store.
const (
	// globalRegisterRate is the steady-state ceiling on registrations
	// processed per second across the whole process for this host.
	globalRegisterRate rate.Limit = 1 // ~1 registration/sec sustained
	// globalRegisterBurst is the token-bucket burst (max registrations
	// that can be accepted back-to-back before the rate kicks in).
	globalRegisterBurst = 10

	// perIPRegisterRate / perIPRegisterBurst are the best-effort per-IP
	// limits. Deliberately tighter than the global limit so that no single
	// (apparent) source can monopolise the global budget.
	perIPRegisterRate  rate.Limit = 0.2 // ~1 registration / 5s per IP
	perIPRegisterBurst int        = 5

	// perIPRetryAfterSeconds / globalRetryAfterSeconds are advisory
	// Retry-After values returned on 429.
	perIPRetryAfterSeconds   = 5
	globalRetryAfterSeconds  = 10
	perIPEvictionInterval    = 10 * time.Minute
	perIPEvictionMaxIdleTime = 10 * time.Minute
)

// registerLimiter bundles the global and per-IP limiters for the
// /-/oauth/register endpoint.
type registerLimiter struct {
	global *rate.Limiter

	mu      sync.Mutex
	perIP   map[string]*perIPEntry
	lastGC  time.Time
	nowFunc func() time.Time // injectable for tests; defaults to time.Now
}

type perIPEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newRegisterLimiter builds a limiter.
//
// maxClients (DCRConfig.MaxClients) is used to size the GLOBAL token
// bucket's burst, i.e. it bounds how many registrations may be accepted in
// a single burst before the steady-state rate throttles further attempts.
//
// SEMANTICS NOTE: maxClients here bounds registrations admitted per burst
// window, NOT the number of simultaneously LIVE clients. A true live cap
// would require a cache SCAN / atomic-decrement primitive that the current
// cache.Cache does not expose; a naive create-only counter would overcount
// as TTL'd clients silently expire and could PERMANENTLY wedge
// registration. We deliberately avoid any counter that can lock the
// endpoint out — the token bucket continuously refills, so it can never
// permanently deny service.
func newRegisterLimiter(maxClients int32) *registerLimiter {
	burst := globalRegisterBurst
	if maxClients > 0 && int(maxClients) < burst {
		// Honour a tighter operator-configured ceiling.
		burst = int(maxClients)
	}
	if burst < 1 {
		burst = 1
	}
	return &registerLimiter{
		global:  rate.NewLimiter(globalRegisterRate, burst),
		perIP:   make(map[string]*perIPEntry),
		nowFunc: time.Now,
	}
}

func (rl *registerLimiter) now() time.Time {
	if rl.nowFunc != nil {
		return rl.nowFunc()
	}
	return time.Now()
}

// allowGlobal reports whether the process-global limiter admits one
// registration. This is the authoritative, non-spoofable guard.
func (rl *registerLimiter) allowGlobal() bool {
	return rl.global.Allow()
}

// allowIP reports whether the best-effort per-IP limiter admits one
// registration from ip. It lazily creates a per-IP bucket and periodically
// evicts idle entries so the map cannot grow unbounded.
func (rl *registerLimiter) allowIP(ip string) bool {
	if ip == "" {
		// No usable IP: don't second-guess the global limiter.
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	rl.gcLocked(now)

	e, ok := rl.perIP[ip]
	if !ok {
		e = &perIPEntry{limiter: rate.NewLimiter(perIPRegisterRate, perIPRegisterBurst)}
		rl.perIP[ip] = e
	}
	e.lastSeen = now
	return e.limiter.Allow()
}

// gcLocked evicts idle per-IP entries. Caller must hold rl.mu.
func (rl *registerLimiter) gcLocked(now time.Time) {
	if now.Sub(rl.lastGC) < perIPEvictionInterval {
		return
	}
	rl.lastGC = now
	for ip, e := range rl.perIP {
		if now.Sub(e.lastSeen) > perIPEvictionMaxIdleTime {
			delete(rl.perIP, ip)
		}
	}
}

// clientIP extracts a best-effort client IP for the per-IP limiter ONLY.
//
// KEY SELECTION: when X-Forwarded-For is present, the rightmost entry
// (the address seen by the nearest proxy hop) is used as the primary
// per-IP key, because it better distinguishes real clients behind a shared
// gateway than RemoteAddr (which is always the gateway's address from
// host-manager's perspective). RemoteAddr is the fallback when XFF is absent.
//
// SECURITY CAVEAT: host-manager does NOT strip client-supplied XFF headers
// (see issue #90), so the XFF value is attacker-controlled and trivially
// spoofable. An adversary can bypass the per-IP limit by rotating IPs or
// XFF values. The per-IP limiter is therefore BEST-EFFORT defense-in-depth
// only. The process-global limiter — which depends on no client-supplied
// value — is the authoritative, non-bypassable guard on registration
// throughput.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := splitAndTrim(xff)
		if len(parts) > 0 {
			// Rightmost entry = address seen by the nearest (trusted) hop.
			if ip := parts[len(parts)-1]; ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func splitAndTrim(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			seg := s[start:i]
			// trim spaces
			for len(seg) > 0 && (seg[0] == ' ' || seg[0] == '\t') {
				seg = seg[1:]
			}
			for len(seg) > 0 && (seg[len(seg)-1] == ' ' || seg[len(seg)-1] == '\t') {
				seg = seg[:len(seg)-1]
			}
			if seg != "" {
				out = append(out, seg)
			}
			start = i + 1
		}
	}
	return out
}
