package host

import (
	"testing"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
	crdsopenapi "kdex.dev/crds/openapi"
)

// The shared scheme registry advertises the OAuth2 authorize endpoint by a
// literal it cannot import from host-manager; it must name the path the host
// actually serves.
func TestSharedSecuritySchemesAdvertiseServedAuthorizePath(t *testing.T) {
	assert.Equal(t, auth.OAuthAuthorizePath, crdsopenapi.OAuthAuthorizePath)
}
