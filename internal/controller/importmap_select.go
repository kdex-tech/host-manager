/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/opencontainers/go-digest"
)

// ImportmapLayer is a minimal descriptor of one layer in an OCI image
// manifest, scoped to what FindImportmapInLayers needs.
type ImportmapLayer struct {
	MediaType string
	Digest    digest.Digest
	Size      int64
}

// LayerFetcher returns the blob bytes for the given layer. The
// caller closes the returned ReadCloser. In production this hits a
// remote registry; in tests it reads from an in-memory map.
type LayerFetcher func(ctx context.Context, layer ImportmapLayer) (io.ReadCloser, error)

// FindImportmapInLayers selects the right layer from a manifest's
// layer list and returns the importmap JSON contents.
//
// Selection rules, in order of preference:
//  1. A layer with mediaType "application/vnd.kdex.importmap+json" —
//     the explicit kdex-cli-tools/package_image artifact type.
//  2. A layer with mediaType "application/json" — raw importmap blob,
//     no tarball wrapping.
//  3. ALL layers with mediaType "application/vnd.oci.image.layer.v1.tar+gzip",
//     sorted by Size ASCENDING. Try each in turn; first whose tarball
//     contains importmap.json wins.
//
// Why "smallest tar+gzip first": the auto-build packager
// (kdex-cli-tools' package_image script) emits TWO tar+gzip layers
// per packages image — a large layer.tar.gz containing node_modules
// plus a copy of importmap.json, then a small importmap.layer.tar.gz
// containing just importmap.json. Iterating manifest.Layers and
// breaking on the first tar+gzip match (the previous behavior) lands
// on the big node_modules layer first. Streaming that to find one
// tiny file is wasteful (hundreds of MB at scale), error-prone, and
// silently picks the wrong copy if the two importmap.json files
// disagree. Size-asc selection prefers the dedicated layer.
func FindImportmapInLayers(ctx context.Context, layers []ImportmapLayer, fetch LayerFetcher) (string, error) {
	// Rule 1: explicit kdex artifact type.
	for _, l := range layers {
		if l.MediaType == "application/vnd.kdex.importmap+json" {
			return readImportmap(ctx, l, fetch)
		}
	}

	// Rule 2: raw JSON layer.
	for _, l := range layers {
		if l.MediaType == "application/json" {
			return readImportmap(ctx, l, fetch)
		}
	}

	// Rule 3: tar+gzip candidates, sorted ascending by Size.
	candidates := make([]ImportmapLayer, 0, len(layers))
	for _, l := range layers {
		if l.MediaType == "application/vnd.oci.image.layer.v1.tar+gzip" {
			candidates = append(candidates, l)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Size < candidates[j].Size
	})

	var lastErr error
	for _, l := range candidates {
		body, err := readImportmap(ctx, l, fetch)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", fmt.Errorf("no tar+gzip layer contained importmap.json (last error: %w)", lastErr)
	}
	return "", fmt.Errorf("no candidate importmap layer found")
}

// readImportmap fetches one layer and returns its importmap.json
// contents. For tar+gzip layers, walks the archive looking for the
// file. For other media types, returns the blob as-is.
func readImportmap(ctx context.Context, layer ImportmapLayer, fetch LayerFetcher) (string, error) {
	rc, err := fetch(ctx, layer)
	if err != nil {
		return "", fmt.Errorf("fetch layer %s: %w", layer.Digest, err)
	}
	defer func() { _ = rc.Close() }()

	if !strings.Contains(layer.MediaType, "tar") {
		data, err := io.ReadAll(rc)
		if err != nil {
			return "", fmt.Errorf("read blob %s: %w", layer.Digest, err)
		}
		return string(data), nil
	}

	gr, err := gzip.NewReader(rc)
	if err != nil {
		return "", fmt.Errorf("gunzip layer %s: %w", layer.Digest, err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar entry in %s: %w", layer.Digest, err)
		}
		clean := path.Clean(header.Name)
		if clean == "importmap.json" || strings.HasSuffix(clean, "/importmap.json") {
			data, err := io.ReadAll(tr)
			if err != nil {
				return "", fmt.Errorf("read importmap.json from tar in %s: %w", layer.Digest, err)
			}
			return string(data), nil
		}
	}
	return "", fmt.Errorf("importmap.json not present in layer %s", layer.Digest)
}
