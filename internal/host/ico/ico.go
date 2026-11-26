package ico

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"kdex.dev/crds/render"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const svgTemplateDefault = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
    <circle cx="50" cy="50" r="48" fill="#000" />
    <text x="50" y="50" 
          font-family="Arial, sans-serif" 
          font-size="60" 
          font-weight="bold"
          fill="white" 
          text-anchor="middle" 
          dominant-baseline="central">[[ .BrandName | trunc 1 ]]</text>
</svg>`

// Ico renders a host's favicon. A host apply builds a new Ico, and the render
// is memoized on that instance only, so a brand or template change shows on
// the next request. It was a package-global cache that kept the first render
// until the process restarted (#305).
//
// Caching headers (Cache-Control, ETag, Last-Modified, the 304) belong to the
// caller, HostHandler.faviconHandler, as they do for every host render.
type Ico struct {
	data     render.TemplateData
	template *template.Template

	once sync.Once
	svg  []byte
	err  error
}

func NewICO(svgTemplate string, data render.TemplateData) *Ico {
	if svgTemplate == "" {
		svgTemplate = svgTemplateDefault
	}

	return &Ico{
		data:     data,
		template: template.Must(template.New("favicon").Funcs(sprig.FuncMap()).Delims("[[", "]]").Parse(svgTemplate)),
	}
}

func (i *Ico) render() ([]byte, error) {
	i.once.Do(func() {
		var buf bytes.Buffer
		if i.err = i.template.Execute(&buf, i.data); i.err == nil {
			i.svg = buf.Bytes()
		}
	})
	return i.svg, i.err
}

func (i *Ico) FaviconHandler(w http.ResponseWriter, r *http.Request) {
	svg, err := i.render()
	if err != nil {
		log := logf.FromContext(r.Context())
		log.Error(err, "error rendering favicon template")
		http.Error(w, fmt.Sprintf("Favicon template error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	// Note: We serve image/svg+xml even for the .ico path
	w.Header().Set("Content-Type", "image/svg+xml")
	if _, err := w.Write(svg); err != nil {
		log := logf.FromContext(r.Context())
		log.Error(err, "failed to write favicon response")
	}
}
