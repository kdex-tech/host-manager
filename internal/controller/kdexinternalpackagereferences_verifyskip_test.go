package controller

import (
	"testing"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// A digest cannot change, so a built image already verified against its pins
// need not be pulled and parsed again on every reconcile. See #161 for the
// verification and #239 for the watch that made re-reconciles more frequent.
func TestAlreadyVerified(t *testing.T) {
	const built = "reg/rsi/packages:6@sha256:abc"
	ipr := func(attrs map[string]string) *kdexv1alpha1.KDexInternalPackageReferences {
		i := &kdexv1alpha1.KDexInternalPackageReferences{}
		i.Status.Attributes = attrs
		return i
	}

	for name, tc := range map[string]struct {
		attrs map[string]string
		want  bool
	}{
		"verified at this digest":        {attrs: map[string]string{"image": built, "verified": "pins"}, want: true},
		"verification was inconclusive":  {attrs: map[string]string{"image": built, "verified": "unknown"}},
		"a different image was verified": {attrs: map[string]string{"image": "reg/rsi/packages:5@sha256:old", "verified": "pins"}},
		"nothing published yet":          {attrs: map[string]string{}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := alreadyVerified(ipr(tc.attrs), built); got != tc.want {
				t.Fatalf("alreadyVerified = %v, want %v", got, tc.want)
			}
		})
	}
}
