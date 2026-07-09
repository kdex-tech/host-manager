package build

import "testing"

func TestImageRef(t *testing.T) {
	const reg = "us-docker.pkg.dev/p/kdex-docker"
	cases := []struct {
		name, prefix, fn, tag, want string
	}{
		{"host-name prefix (default)", "rsi-dev/", "feedback", "latest", reg + "/rsi-dev/feedback:latest"},
		{"shared prefix", "fn/", "feedback", "7", reg + "/fn/feedback:7"},
		{"flat prefix", "", "feedback", "latest", reg + "/feedback:latest"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := imageRef(reg, c.prefix, c.fn, c.tag); got != c.want {
				t.Fatalf("imageRef = %q, want %q", got, c.want)
			}
		})
	}
}
