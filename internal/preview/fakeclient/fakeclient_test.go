package fakeclient

import (
	"context"
	"testing"

	"github.com/kdex-tech/host-manager/internal/preview/loader"
)

func TestSetup_RunsPageReconciler(t *testing.T) {
	snap, err := loader.Load("../loader/testdata/single")
	if err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	fc, err := Setup(context.Background(), snap)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if fc.HostHandler == nil {
		t.Fatal("HostHandler is nil")
	}
	if fc.CacheManager == nil {
		t.Fatal("CacheManager is nil")
	}
}
