package auth

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
)

// NewExchanger must accept and retain an EventDispatcher (nil is allowed).
func TestNewExchanger_AcceptsEventDispatcher(t *testing.T) {
	g := NewWithT(t)
	d := NewEventDispatcher("h", nil, logr.Discard())
	ex, err := NewExchanger(context.Background(), Config{}, nil, nil, d)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ex).ToNot(BeNil())
	g.Expect(ex.eventDispatcher).To(Equal(d))
}

// NewExchanger must also accept a nil EventDispatcher, and the resulting
// Exchanger's EmitLogout must remain a safe no-op-like call (no panic).
func TestNewExchanger_NilEventDispatcher(t *testing.T) {
	g := NewWithT(t)
	ex, err := NewExchanger(context.Background(), Config{}, nil, nil, nil)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ex).ToNot(BeNil())
	g.Expect(ex.eventDispatcher).To(BeNil())

	g.Expect(func() { ex.EmitLogout(context.Background(), "rt-id", "id-token") }).ToNot(Panic())
}
