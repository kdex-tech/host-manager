package ico

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"kdex.dev/crds/render"
)

// Each host apply builds a new Ico, and it must render that apply's brand.
// The render was memoized in a package global, so the first brand served
// stuck until the process restarted (#305).
func TestFaviconHandler_RendersEachInstancesBrand(t *testing.T) {
	get := func(i *Ico) string {
		rr := httptest.NewRecorder()
		i.FaviconHandler(rr, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "image/svg+xml", rr.Header().Get("Content-Type"))
		assert.Empty(t, rr.Header().Get("Cache-Control"), "caching headers belong to the caller")
		return rr.Body.String()
	}

	a := NewICO("", render.TemplateData{BrandName: "Alpha"})
	assert.Contains(t, get(a), ">A</text>")
	assert.Contains(t, get(a), ">A</text>", "a repeat request serves the memo")

	b := NewICO("", render.TemplateData{BrandName: "Beta"})
	assert.Contains(t, get(b), ">B</text>")
}
