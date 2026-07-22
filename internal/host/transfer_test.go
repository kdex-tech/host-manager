package host

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	. "github.com/onsi/gomega"
)

func TestTransferRecordRoundTrip(t *testing.T) {
	g := NewWithT(t)
	ttl := time.Minute
	mgr, _ := cache.NewCacheManager("", "", &ttl)
	hh := &HostHandler{cacheManager: mgr}
	ctx := context.Background()

	rec := transferRecord{
		JTI:          "j1",
		Sub:          "alice",
		Entitlements: []string{"functions:/api/v1/files:read"},
		Target:       TransferTarget{Method: "GET", Path: "/api/v1/files/abc/content"},
	}
	g.Expect(hh.storeTransferRecord(ctx, "h1", rec, time.Minute)).ToNot(HaveOccurred())

	got, ok := hh.loadTransferRecord(ctx, "h1")
	g.Expect(ok).To(BeTrue())
	g.Expect(got).To(Equal(rec))

	_, ok = hh.loadTransferRecord(ctx, "missing")
	g.Expect(ok).To(BeFalse())
}

func TestNewTransferHandleUnique(t *testing.T) {
	g := NewWithT(t)
	a, err := newTransferHandle()
	g.Expect(err).ToNot(HaveOccurred())
	b, _ := newTransferHandle()
	g.Expect(a).ToNot(Equal(b))
	g.Expect(len(a)).To(BeNumerically(">=", 43)) // 32 bytes base64url (no pad)
}

func TestTransferBaseURL(t *testing.T) {
	g := NewWithT(t)
	r := httptest.NewRequest("POST", "https://ignored/api/v1/mcp", nil)
	r.Header.Set("X-Forwarded-Host", "dev.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	g.Expect(transferBaseURL(r)).To(Equal("https://dev.example"))
}
