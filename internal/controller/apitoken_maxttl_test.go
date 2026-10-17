package controller

import (
	"testing"
	"time"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// KDexHost.spec.auth.apiToken.maxTTL reaches the host's TokenManager through
// resolveAPITokenMaxTTL. See kdex-tech/host-manager#238.
func TestResolveAPITokenMaxTTL(t *testing.T) {
	for name, tc := range map[string]struct {
		auth    *kdexv1alpha1.Auth
		want    time.Duration
		wantErr bool
	}{
		"no auth":     {auth: nil},
		"no apiToken": {auth: &kdexv1alpha1.Auth{}},
		"unset":       {auth: &kdexv1alpha1.Auth{APIToken: &kdexv1alpha1.APIToken{TokenPrefix: "acme_pat_"}}},
		"set":         {auth: &kdexv1alpha1.Auth{APIToken: &kdexv1alpha1.APIToken{MaxTTL: "2160h"}}, want: 2160 * time.Hour},
		// CEL refuses these at admission; a value that slips past it must not
		// silently unbound the host.
		"unparseable": {auth: &kdexv1alpha1.Auth{APIToken: &kdexv1alpha1.APIToken{MaxTTL: "90d"}}, wantErr: true},
		"zero":        {auth: &kdexv1alpha1.Auth{APIToken: &kdexv1alpha1.APIToken{MaxTTL: "0s"}}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := resolveAPITokenMaxTTL(tc.auth)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("maxTTL = %s, want %s", got, tc.want)
			}
		})
	}
}
