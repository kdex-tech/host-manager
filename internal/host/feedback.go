package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kdex-tech/host-manager/internal/auth"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/sniffer"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type FeedbackTheme struct {
	// CLI Colors (ANSI)
	CLIHeader  string
	CLISuccess string
	CLIWarning string
	CLIDim     string
	CLILineNum string
	CLIReset   string

	// HTML Colors (CSS)
	BgPage        string
	BgSidebar     string
	BgCard        string
	BgCode        string
	Border        string
	TextPrimary   string
	TextSecondary string
	TextAccent    string
	TextLint      string
	TextCode      string
	MethodGet     string
	MethodPost    string
	MethodPut     string
	MethodDelete  string
	BtnSuccess    string
	BtnHover      string
}

var defaultTheme = FeedbackTheme{
	CLIHeader:  "\033[1;36m",
	CLISuccess: "\033[1;32m",
	CLIWarning: "\033[1;33m",
	CLIDim:     "\033[2m",
	CLILineNum: "\033[90m",
	CLIReset:   "\033[0m",

	BgPage:        "#0d1117",
	BgSidebar:     "#161b22",
	BgCard:        "#21262d",
	BgCode:        "#1e1e1e",
	Border:        "#30363d",
	TextPrimary:   "#c9d1d9",
	TextSecondary: "#8b949e",
	TextAccent:    "#58a6ff",
	TextLint:      "#d29922",
	TextCode:      "#9cdcfe",
	MethodGet:     "#238636",
	MethodPost:    "#1f6feb",
	MethodPut:     "#9e6a03",
	MethodDelete:  "#da3633",
	BtnSuccess:    "#238636",
	BtnHover:      "#2ea043",
}

// AnalysisCache stores the results of the InferenceEngine for a short period
// so that the redirected user can view the report.
type AnalysisCache struct {
	entries sync.Map
}

type cachedAnalysis struct {
	Result    *sniffer.AnalysisResult
	Timestamp time.Time
}

func NewAnalysisCache() *AnalysisCache {
	ac := &AnalysisCache{}
	go ac.reap()
	return ac
}

func (ac *AnalysisCache) Store(result *sniffer.AnalysisResult) string {
	id := uuid.New().String()
	ac.entries.Store(id, cachedAnalysis{
		Result:    result,
		Timestamp: time.Now(),
	})
	return id
}

func (ac *AnalysisCache) Get(id string) (*sniffer.AnalysisResult, bool) {
	val, ok := ac.entries.Load(id)
	if !ok {
		return nil, false
	}
	return val.(cachedAnalysis).Result, true
}

func (ac *AnalysisCache) reap() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		ac.entries.Range(func(key, value any) bool {
			entry := value.(cachedAnalysis)
			if now.Sub(entry.Timestamp) > 10*time.Minute {
				ac.entries.Delete(key)
			}
			return true
		})
	}
}

// isAgent detects AI agents and crawlers by checking for known bot identifiers in the user-agent string.
// This uses specific bot names to avoid false positives from overly broad patterns.
func isAgent(userAgent string) bool {
	userAgent = strings.ToLower(userAgent)

	// Common AI agent patterns
	agentPatterns := []string{
		// OpenAI
		"gptbot",
		"chatgpt-user",

		// Anthropic
		"claude-web",
		"anthropic-ai",

		// Google AI
		"google-extended",
		"googlebot",
		"bard",
		"gemini",

		// Perplexity
		"perplexitybot",
		"perplexity",

		// Other AI services
		"cohere-ai",
		"ai2bot",

		// Common crawlers
		"ccbot",      // Common Crawl
		"bytespider", // ByteDance/TikTok
		"applebot",
		"facebookbot",
		"twitterbot",
		"linkedinbot",
		"slackbot",
		"discordbot",

		// Generic bot indicators (more specific)
		"bot/",
		"crawler",
		"spider",
		"scraper",
	}

	for _, pattern := range agentPatterns {
		if strings.Contains(userAgent, pattern) {
			return true
		}
	}

	return false
}

// User-Agent detection for CLI tools
func isCLI(userAgent string) bool {
	userAgent = strings.ToLower(userAgent)
	return strings.Contains(userAgent, "curl") ||
		strings.Contains(userAgent, "wget") ||
		strings.Contains(userAgent, "httpie")
}

func (hh *HostHandler) DesignMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := logf.FromContext(r.Context())

		// Snapshot the fields we need and release the RLock IMMEDIATELY.
		// Pre-#82 the outer RLock was held across hh.serveError /
		// hh.unwrap, both of which call hh.serveError — which itself
		// takes hh.mu.RLock. Go's RWMutex prohibits recursive read
		// locking, so a writer queued between the outer and inner
		// RLock deadlocked the host. Same shape as #26 and #51.
		hh.mu.RLock()
		mux := hh.Mux
		sniffer := hh.sniffer
		hh.mu.RUnlock()

		h, p := mux.Handler(r)
		if p == "" {
			log.V(2).Info("request did not match", "url", r.URL.String())
		} else {
			log.V(2).Info("request match", "url", r.URL.String(), "pattern", p)
		}

		ew := &errorResponseWriter{ResponseWriter: w}
		wrapped := wrappedErrorResponseWriter(ew, w)

		// Only intercept if we have a sniffer (checker), it's not an internal path
		if sniffer == nil || (strings.HasPrefix(r.URL.Path, "/-/") && p != "") {
			next.ServeHTTP(wrapped, r)
			hh.unwrap(ew, r, w)
			return
		}

		// We should only invoke the sniffer if:
		// - there is no handler, OR
		// - if the handler is a KDexFunctionHandler AND the function is
		//   mutable AND we have X-KDex-* headers
		invokeSniffer := false
		if p != "" {
			var matchedFunction *kdexv1alpha1.KDexFunction
			if fh, ok := h.(*KDexFunctionHandler); ok {
				matchedFunction = fh.Function
				log.V(2).Info("matched KDexFunction", "name", matchedFunction.Name)
			}

			// We don't want to invoke the sniffer on an existing mutable function
			// when there are no X-KDex-* headers because this allows us to test
			// the function implementation. The sniffer bypasses the
			// implementation and directly serves the feedback page.
			hasKDexHeader := false
			for k := range r.Header {
				if strings.HasPrefix(k, "X-KDex-") {
					hasKDexHeader = true
					break
				}
			}

			if matchedFunction != nil && isMutable(matchedFunction) && hasKDexHeader {
				invokeSniffer = true
			}
		} else {
			// No handler matched, so we should invoke the sniffer
			invokeSniffer = true
		}

		// Create a wrapper to capture the status code
		if invokeSniffer && !hh.canGenerateSniffer(r.Context()) {
			log.V(1).Info("sniffer suppressed: caller lacks functions:create entitlement", "path", r.URL.Path)
			// The 404 that follows is truthful -- the path does not exist,
			// which is why the sniffer was reached. But suppression was
			// previously visible only at V(1), which is why "I expected a
			// 303, got 404" is a documented question. Name the missing
			// entitlement in a header so curl -i answers it, without
			// relabelling an absence as a denial.
			//
			// Only for a caller whose subject was actually evaluated.
			// canGenerateSniffer refuses an anonymous caller -- no
			// AuthContext, or one with an empty subject -- before
			// CheckAccess runs, and naming the entitlement there would
			// advertise the gate rather than explain a decision about them.
			// hasEvaluatedSubject uses canGenerateSniffer's own definition
			// of anonymous so the two can never disagree.
			if hasEvaluatedSubject(r.Context()) {
				w.Header().Set("X-KDex-Sniffer-Suppressed", "functions:create")
			}
			invokeSniffer = false
		}

		if invokeSniffer {
			// Body Persistence: Read body so we can restore it for the next handler AND the sniffer
			var bodyBytes []byte
			if r.Body != nil {
				bodyBytes, _ = io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			// Analyze
			result, err := sniffer.Analyze(r)
			if err != nil {
				log.Error(err, "failed to analyze request", "path", r.URL.Path)
				// Fallback to standard error serving if analysis fails
				if p == "" {
					hh.serveError(w, r, http.StatusNotFound, "not found")
				} else {
					hh.serveError(w, r, http.StatusBadRequest, err.Error())
				}
				return
			}

			if result == nil || result.Function == nil {
				if p == "" {
					hh.serveError(w, r, http.StatusNotFound, "not found")
				} else {
					hh.serveError(w, r, ew.statusCode, ew.statusMsg)
				}
				return
			}

			// Store result
			id := hh.analysisCache.Store(result)

			// Smart Redirection
			format := "html"
			if isAgent(r.UserAgent()) {
				format = "json"
			} else if isCLI(r.UserAgent()) || strings.Contains(r.Header.Get("Accept"), "text/plain") {
				format = "text"
			}

			inspectURL := fmt.Sprintf("/-/sniffer/inspect/%s?format=%s", id, format)
			absoluteURL := fmt.Sprintf("%s%s", ko.Host(r), inspectURL)

			w.Header().Set("Location", inspectURL)
			w.Header().Set("X-KDex-Sniffer-Docs", "/-/sniffer/docs")
			w.WriteHeader(http.StatusSeeOther)

			// Fallback body for those who don't follow redirects
			// Use OSC 8 for clickable link
			link := fmt.Sprintf("\033]8;;%s\033\\%s\033]8;;\033\\", absoluteURL, absoluteURL)
			_, err = fmt.Fprintf(w, "➔ API Draft Created. View at: %s\n(Note: Use 'curl -L' to follow automatically).\n", link)
			if err != nil {
				hh.serveError(w, r, http.StatusInternalServerError, err.Error())
			}
		} else {
			next.ServeHTTP(wrapped, r)
			hh.unwrap(ew, r, w)
		}
	})
}

func (hh *HostHandler) unwrap(ew *errorResponseWriter, r *http.Request, w http.ResponseWriter) {
	if ew.statusCode >= 400 {
		// Check if the client accepts HTML
		if acceptsHTML(r) {
			// Clear headers before calling serveError: previous handlers
			// (like ReverseProxy) may have set headers -- notably
			// Content-Length -- describing a body we've suppressed.
			//
			// WWW-Authenticate is exempt because it is REQUIRED on a 401
			// (RFC 7235); deleting it produced a bare 401 for every
			// HTML-accepting client and silently disabled OAuth discovery
			// for browsers. It describes the rejection, not the body being
			// replaced. Add a header here only when something actually sets
			// it -- everything else is exactly what the wipe exists for.
			//
			// X-KDex-Sniffer-Suppressed is exempt for the same reason: it
			// names the entitlement the caller lacked when sniffer
			// generation was suppressed (see DesignMiddleware above), and
			// without the exemption it would be wiped for every
			// HTML-accepting caller before it ever reached a browser.
			//
			// CONSTRAINT: this snapshots via Get/Set, which keeps only the
			// FIRST value of a header. Every allow-listed header is
			// single-valued today (both are written with .Set). A producer
			// that ever uses .Add on one of these would silently lose its
			// extra values here -- add such a header to the list only after
			// switching this loop to header.Values/textproto append.
			header := w.Header()
			preserved := map[string]string{}
			for _, k := range []string{"WWW-Authenticate", "X-KDex-Sniffer-Suppressed"} {
				if v := header.Get(k); v != "" {
					preserved[k] = v
				}
			}
			for k := range header {
				delete(header, k)
			}
			for k, v := range preserved {
				header.Set(k, v)
			}

			// Write the buffered status code structure
			hh.serveError(w, r, ew.statusCode, ew.statusMsg)
		} else {
			// Preserve original Content-Type if set, otherwise fallback to plain text
			if w.Header().Get("Content-Type") == "" {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			}
			w.WriteHeader(ew.statusCode)
			_, _ = w.Write([]byte(ew.statusMsg))
		}
	}
}

// A mutable function means that it does not have a spec.origin.executable or
// spec.origin.source which implies it is relying on code generation and we can
// influence the spec through the sniffer.
func isMutable(matchedFunction *kdexv1alpha1.KDexFunction) bool {
	return matchedFunction.Spec.GetOrigin().Executable == nil ||
		matchedFunction.Spec.GetOrigin().Source == nil
}

// hasEvaluatedSubject reports whether ctx carries an AuthContext with a
// non-empty subject -- i.e. a caller canGenerateSniffer would treat as
// logged in rather than anonymous. Both canGenerateSniffer and the sniffer-
// suppression header in DesignMiddleware key off this single definition of
// "anonymous" so they can never disagree about which callers get named.
func hasEvaluatedSubject(ctx context.Context) bool {
	authContext, ok := auth.GetAuthContext(ctx)
	if !ok {
		return false
	}
	sub, _ := authContext.GetSubject()
	return sub != ""
}

// canGenerateSniffer reports whether the caller is permitted to auto-generate
// KDexFunctions via the Request Sniffer. The caller must be logged in (have an
// AuthContext with a subject) and hold the `functions:create` entitlement. When
// no authChecker is wired (e.g. a host with auth disabled) the check is skipped
// so the sniffer keeps working in dev contexts that never configured auth.
func (hh *HostHandler) canGenerateSniffer(ctx context.Context) bool {
	if hh.authChecker == nil {
		return true
	}

	if !hasEvaluatedSubject(ctx) {
		return false
	}

	requirement := kdexv1alpha1.SecurityRequirement{
		"bearer": []string{"functions:create"},
	}
	authorized, err := hh.authChecker.CheckAccess(
		ctx,
		"functions",
		"*",
		[]kdexv1alpha1.SecurityRequirement{requirement},
		"create",
	)
	return err == nil && authorized
}

// InspectHandler serves the feedback UI
func (hh *HostHandler) InspectHandler(w http.ResponseWriter, r *http.Request) {
	hh.mu.RLock()
	defer hh.mu.RUnlock()

	id := r.PathValue("uuid")
	format := r.URL.Query().Get("format")

	result, ok := hh.analysisCache.Get(id)
	if !ok {
		http.Error(w, "Analysis result expired or not found.", http.StatusNotFound)
		return
	}

	// Generate OpenAPI spec snippet
	spec := hh.GetOpenAPIBuilder().BuildOneOff(ko.Host(r), result.Function)
	specBytes, _ := json.MarshalIndent(spec, "", "  ")
	specStr := string(specBytes)

	var out bytes.Buffer

	if format == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(&out, "%s─── API DESIGN FEEDBACK ───%s\n\n", defaultTheme.CLIHeader, defaultTheme.CLIReset)
		fmt.Fprintf(&out, "%s✓ Analyzed Request:%s %s %s\n", defaultTheme.CLISuccess, defaultTheme.CLIReset, result.OriginalRequest.Method, result.OriginalRequest.URL.Path)

		if len(result.Lints) > 0 {
			fmt.Fprintf(&out, "\n%sWarnings / Insights:%s\n", defaultTheme.CLIWarning, defaultTheme.CLIReset)
			for _, lint := range result.Lints {
				fmt.Fprintf(&out, "  • %s\n", lint)
			}
		}

		fmt.Fprintf(&out, "\n%sGenerated OpenAPI Spec (Fragment):%s\n", defaultTheme.CLIDim, defaultTheme.CLIReset)
		lines := strings.Split(specStr, "\n")
		for i, line := range lines {
			if line == "" && i == len(lines)-1 {
				break
			}
			fmt.Fprintf(&out, "%s%4d │ %s%s\n", defaultTheme.CLILineNum, i+1, defaultTheme.CLIReset, line)
		}

		_, err := w.Write(out.Bytes())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	} else if format == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		responseBody := map[string]any{}
		feedback := map[string]any{
			"method": result.OriginalRequest.Method,
			"path":   result.OriginalRequest.URL.Path,
		}

		if len(result.Lints) > 0 {
			lints := append([]string{}, result.Lints...)
			feedback["lints"] = lints
		}

		responseBody["feedback"] = feedback
		responseBody["spec"] = spec

		err := json.NewEncoder(w).Encode(responseBody)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// HTML Dashboard
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprintf(&out, `<!DOCTYPE html>
<html>
<head>
	<title>KDex API Workbench</title>
	<style>
		body { margin: 0; font-family: 'Inter', system-ui, sans-serif; background: %[1]s; color: %[2]s; display: grid; grid-template-columns: 350px 1fr; height: 100vh; overflow: hidden; }
		.sidebar { background: %[3]s; border-right: 1px solid %[4]s; padding: 20px; overflow-y: auto; }
		.main { padding: 20px; overflow-y: auto; display: flex; flex-direction: column; }
		h1 { font-size: 16px; margin: 0 0 20px; color: %[5]s; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
		h2 { font-size: 14px; margin: 20px 0 10px; color: %[6]s; border-bottom: 1px solid %[4]s; padding-bottom: 5px; }
		.card { background: %[7]s; border: 1px solid %[4]s; border-radius: 6px; padding: 15px; margin-bottom: 15px; }
		.method { display: inline-block; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 12px; margin-right: 8px; }
		.method.GET { background: %[8]s; color: white; }
		.method.POST { background: %[9]s; color: white; }
		.method.PUT { background: %[10]s; color: white; }
		.method.DELETE { background: %[11]s; color: white; }
		.lint-item { margin-bottom: 8px; font-size: 13px; display: flex; gap: 8px; align-items: flex-start; }
		.lint-icon { color: %[12]s; }
		pre { margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 13px; }
		code { display: block; padding: 15px; background: %[13]s; color: %[14]s; border-radius: 6px; overflow-x: auto; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
		.ln { color: %[5]s; opacity: 0.5; margin-right: 15px; user-select: none; border-right: 1px solid %[4]s; padding-right: 10px; display: inline-block; min-width: 30px; text-align: right; }
		.lc { color: %[14]s; }
		.toolbar { display: flex; justify-content: flex-end; margin-bottom: 10px; }
		button { background: %[15]s; color: white; border: none; padding: 6px 12px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
		button:hover { background: %[16]s; }
	</style>
</head>
<body>
	<div class="sidebar">
		<h1>API Workbench</h1>
		
		<div class="card">
			<div style="font-size: 12px; color: %[6]s; margin-bottom: 4px;">Request Invariants</div>
			<div style="font-family: monospace; font-size: 14px;">
				<span class="method %[17]s">%[17]s</span>
				<span title="%[18]s">%[18]s</span>
			</div>
		</div>

		<h2>Analysis & Linting</h2>
		%[19]s
	</div>
	<div class="main">
		<div class="toolbar">
			<button onclick="navigator.clipboard.writeText(document.querySelector('code').innerText); this.innerText='Copied!'">Copy Spec Fragment</button>
		</div>
		<pre><code>%[20]s</code></pre>
	</div>
</body>
</html>`,
		defaultTheme.BgPage,
		defaultTheme.TextPrimary,
		defaultTheme.BgSidebar,
		defaultTheme.Border,
		defaultTheme.TextAccent,
		defaultTheme.TextSecondary,
		defaultTheme.BgCard,
		defaultTheme.MethodGet,
		defaultTheme.MethodPost,
		defaultTheme.MethodPut,
		defaultTheme.MethodDelete,
		defaultTheme.TextLint,
		defaultTheme.BgCode,
		defaultTheme.TextCode,
		defaultTheme.BtnSuccess,
		defaultTheme.BtnHover,
		result.OriginalRequest.Method,
		result.OriginalRequest.URL.Path,
		generateLintHTML(result.Lints),
		renderSpecHTML(specStr))

	_, err := w.Write(out.Bytes())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func generateLintHTML(lints []string) string {
	if len(lints) == 0 {
		return fmt.Sprintf(`<div style="font-size: 13px; color: %s; font-style: italic;">No linting issues found.</div>`, defaultTheme.TextSecondary)
	}
	var b strings.Builder
	for _, l := range lints {
		fmt.Fprintf(&b, `<div class="lint-item"><span class="lint-icon" style="color: %s">⚠</span> <span>%s</span></div>`, defaultTheme.TextLint, htmlEscape(l))
	}
	return b.String()
}

func htmlEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "&", "&amp;"), "<", "&lt;")
}

func renderSpecHTML(spec string) string {
	lines := strings.Split(spec, "\n")
	var b strings.Builder
	for i, line := range lines {
		if line == "" && i == len(lines)-1 {
			break
		}
		// We use a separate span for the line number and the content
		fmt.Fprintf(&b, `<span class="ln">%d</span><span class="lc">%s</span>`+"\n", i+1, htmlEscape(line))
	}
	return b.String()
}
