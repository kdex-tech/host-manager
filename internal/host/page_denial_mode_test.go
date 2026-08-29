package host

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
)

// The knob used to fail OPEN on a typo: SetPageDenialMode maps anything that
// is not exactly "forbid" to PageDenialDiscover -- the LESS strict mode -- and
// cmd/main.go validated nothing, so `forbidden`, `Forbid` or a trailing space
// silently bought the opposite of what the operator asked for. IsValid is what
// cmd/main.go now refuses to start on.
func TestPageDenialModeIsValid(t *testing.T) {
	valid := []PageDenialMode{PageDenialDiscover, PageDenialForbid}
	for _, m := range valid {
		if !m.IsValid() {
			t.Fatalf("IsValid(%q) = false, want true", m)
		}
	}
	// Every one of these used to resolve silently to discover.
	invalid := []PageDenialMode{"", "forbidden", "Forbid", "forbid ", " forbid", "FORBID", "deny", "discover\n"}
	for _, m := range invalid {
		if m.IsValid() {
			t.Fatalf("IsValid(%q) = true, want false: an unrecognised mode must not start the controller", m)
		}
	}
}

// The setter keeps coercing -- it is the safety net behind cmd/main.go's
// check, not the check itself -- and still resolves to the strict-by-default
// pair correctly for the two real values.
func TestSetPageDenialModeCoercesUnknownToDiscover(t *testing.T) {
	cm, _ := cache.NewCacheManager("", "page-denial-mode-test", nil)
	for in, want := range map[PageDenialMode]PageDenialMode{
		PageDenialForbid:   PageDenialForbid,
		PageDenialDiscover: PageDenialDiscover,
		"":                 PageDenialDiscover,
		"forbidden":        PageDenialDiscover,
	} {
		hh := NewHostHandler(nil, "t", "default", logr.Discard(), cm)
		hh.SetPageDenialMode(in)
		if hh.pageDenialMode != want {
			t.Fatalf("SetPageDenialMode(%q) = %q, want %q", in, hh.pageDenialMode, want)
		}
	}
}
