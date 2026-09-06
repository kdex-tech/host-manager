package host

import (
	"net/http"
	"testing"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func fnWithAnnotation(v string) *kdexv1alpha1.KDexFunction {
	f := &kdexv1alpha1.KDexFunction{}
	if v != "" {
		f.ObjectMeta = metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationInvalidatesGrantsOnWrite: v,
		}}
	}
	return f
}

func TestShouldInvalidateGrants(t *testing.T) {
	cases := []struct {
		name   string
		fn     *kdexv1alpha1.KDexFunction
		method string
		status int
		want   bool
	}{
		{"annotated 2xx DELETE", fnWithAnnotation("true"), http.MethodDelete, 204, true},
		{"annotated 2xx POST", fnWithAnnotation("true"), http.MethodPost, 201, true},
		{"annotated GET", fnWithAnnotation("true"), http.MethodGet, 200, false},
		{"annotated HEAD", fnWithAnnotation("true"), http.MethodHead, 200, false},
		{"annotated POST 4xx", fnWithAnnotation("true"), http.MethodPost, 403, false},
		{"annotated POST 5xx", fnWithAnnotation("true"), http.MethodPost, 500, false},
		{"not annotated POST", fnWithAnnotation(""), http.MethodPost, 201, false},
		{"annotation false", fnWithAnnotation("false"), http.MethodPost, 201, false},
		{"nil fn", nil, http.MethodPost, 201, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldInvalidateGrants(tc.fn, tc.method, tc.status); got != tc.want {
				t.Fatalf("shouldInvalidateGrants = %v, want %v", got, tc.want)
			}
		})
	}
}
