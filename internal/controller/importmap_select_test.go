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
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

// Scenario 2 reproducer + corrected algorithm validator.
//
// Background: the previous PullImportMap (kdexinternalhost_controller.go)
// did:
//
//	for _, layer := range manifest.Layers {
//	    if layer.MediaType == "application/json" ||
//	        layer.MediaType == "application/vnd.kdex.importmap+json" ||
//	        layer.MediaType == "application/vnd.oci.image.layer.v1.tar+gzip" {
//	        layerDescriptor = ...; break
//	    }
//	}
//
// On an auto-build packages image, the packager (cli-tools'
// package_image script) pushes TWO tar+gzip layers: first the big
// node_modules layer, then the small dedicated importmap layer.
// Iterating + breaking on the first match lands on the big layer.
// The tests below pin the corrected size-asc selection and exercise
// the supporting rules.

// ----- helpers -----

// makeTarGz produces a gzipped tar archive containing the given
// files. Returns the bytes + a content-addressed digest.
func makeTarGz(t *testing.T, files map[string]string) ([]byte, digest.Digest) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	// Iterate map in name order so the produced archive is stable.
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	// Avoid pulling in sort by using a manual insertion-sort —
	// these tests have at most a handful of files.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	for _, name := range names {
		body := files[name]
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	data := buf.Bytes()
	sum := sha256.Sum256(data)
	return data, digest.NewDigestFromHex("sha256", hex.EncodeToString(sum[:]))
}

// blobs maps digest -> raw bytes. Lets a test pass a synthetic
// LayerFetcher that satisfies fetches without a real registry.
type blobs map[digest.Digest][]byte

func (b blobs) fetcher() LayerFetcher {
	return func(_ context.Context, l ImportmapLayer) (io.ReadCloser, error) {
		data, ok := b[l.Digest]
		if !ok {
			return nil, errors.New("digest not in test blob store: " + string(l.Digest))
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
}

func layer(mediaType string, dgst digest.Digest, size int) ImportmapLayer {
	return ImportmapLayer{MediaType: mediaType, Digest: dgst, Size: int64(size)}
}

// ----- tests -----

func TestFindImportmapInLayers_KdexMediaType_PreferredAboveAll(t *testing.T) {
	// If the manifest has an explicit kdex artifact-typed layer,
	// it wins regardless of what else is around.
	store := blobs{}
	wantBody := `{"imports":{"react":"/-/modules/react/index.js"}}`

	kdexDigest := digest.NewDigestFromHex("sha256", strings.Repeat("a", 64))
	store[kdexDigest] = []byte(wantBody)

	// A misleading tar+gzip layer that would otherwise also be matched.
	tarBytes, tarDigest := makeTarGz(t, map[string]string{
		"importmap.json": `{"imports":{"WRONG":"this should be skipped"}}`,
	})
	store[tarDigest] = tarBytes

	layers := []ImportmapLayer{
		layer("application/vnd.oci.image.layer.v1.tar+gzip", tarDigest, len(tarBytes)),
		layer("application/vnd.kdex.importmap+json", kdexDigest, len(wantBody)),
	}

	got, err := FindImportmapInLayers(context.Background(), layers, store.fetcher())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantBody {
		t.Errorf("wrong layer picked.\n got: %s\nwant: %s", got, wantBody)
	}
}

func TestFindImportmapInLayers_RawJSONLayer_PreferredOverTarGzip(t *testing.T) {
	store := blobs{}
	wantBody := `{"imports":{"react":"/-/modules/react/index.js"}}`

	jsonDigest := digest.NewDigestFromHex("sha256", strings.Repeat("b", 64))
	store[jsonDigest] = []byte(wantBody)

	tarBytes, tarDigest := makeTarGz(t, map[string]string{
		"importmap.json": `{"imports":{"WRONG":"tar layer should lose"}}`,
	})
	store[tarDigest] = tarBytes

	layers := []ImportmapLayer{
		layer("application/vnd.oci.image.layer.v1.tar+gzip", tarDigest, len(tarBytes)),
		layer("application/json", jsonDigest, len(wantBody)),
	}

	got, err := FindImportmapInLayers(context.Background(), layers, store.fetcher())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantBody {
		t.Errorf("raw JSON layer not preferred.\n got: %s\nwant: %s", got, wantBody)
	}
}

func TestFindImportmapInLayers_SingleTarGzip(t *testing.T) {
	// Simplest auto-build shape: one tar+gzip layer, importmap.json
	// at the archive root. Mirrors a hypothetical packager that
	// emitted only the dedicated importmap layer (no node_modules).
	store := blobs{}
	wantBody := `{"imports":{"react":"/-/modules/react/index.js"}}`

	tarBytes, tarDigest := makeTarGz(t, map[string]string{
		"importmap.json": wantBody,
	})
	store[tarDigest] = tarBytes

	layers := []ImportmapLayer{
		layer("application/vnd.oci.image.layer.v1.tar+gzip", tarDigest, len(tarBytes)),
	}

	got, err := FindImportmapInLayers(context.Background(), layers, store.fetcher())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantBody {
		t.Errorf("got %q, want %q", got, wantBody)
	}
}

func TestFindImportmapInLayers_TwoTarGzip_BigFirst_PrefersSmaller(t *testing.T) {
	// THIS IS THE BUG-REPRODUCER.
	//
	// The real packager produces this exact shape: layer.tar.gz
	// (PACKAGING_DIR root, includes node_modules + a copy of
	// importmap.json) FIRST, then importmap.layer.tar.gz (just
	// importmap.json) SECOND. The big layer is ~100 MB at production
	// scale; the small layer is a few KiB.
	//
	// Old PullImportMap iterated manifest.Layers and broke on the
	// first tar+gzip — i.e. the BIG layer. The test below asserts the
	// corrected behaviour: prefer the smaller layer, which is the
	// dedicated importmap layer with the authoritative content.
	store := blobs{}

	// Build the big layer with a misleading importmap content. Pad
	// the big layer with junk so its compressed Size dwarfs the small
	// one. (Real node_modules are 100s of MB compressed; here we
	// only need the relative order to be unambiguous.)
	bigJunk := strings.Repeat("/* node_modules junk */ ", 4096)
	bigFiles := map[string]string{
		"node_modules/react/index.js":     bigJunk,
		"node_modules/react-dom/index.js": bigJunk,
		"importmap.json":                  `{"imports":{"WRONG":"BIG-layer copy"}}`,
	}
	bigBytes, bigDigest := makeTarGz(t, bigFiles)
	store[bigDigest] = bigBytes

	smallBody := `{"imports":{"CORRECT":"dedicated-importmap-layer"}}`
	smallFiles := map[string]string{"importmap.json": smallBody}
	smallBytes, smallDigest := makeTarGz(t, smallFiles)
	store[smallDigest] = smallBytes

	if len(smallBytes) >= len(bigBytes) {
		t.Fatalf("test setup: small layer (%d) should compress smaller than big layer (%d)",
			len(smallBytes), len(bigBytes))
	}

	// Manifest order matches package_image's oras push order:
	// big layer FIRST, importmap layer SECOND. Old "break on first"
	// would pick big; corrected size-asc picks small.
	layers := []ImportmapLayer{
		layer("application/vnd.oci.image.layer.v1.tar+gzip", bigDigest, len(bigBytes)),
		layer("application/vnd.oci.image.layer.v1.tar+gzip", smallDigest, len(smallBytes)),
	}

	got, err := FindImportmapInLayers(context.Background(), layers, store.fetcher())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != smallBody {
		t.Errorf("wrong layer picked.\n got:  %s\nwant: %s", got, smallBody)
	}
}

func TestFindImportmapInLayers_OldBrokenAlgorithm_PicksWrongLayer(t *testing.T) {
	// Snapshot of the OLD broken selection logic, kept here so the
	// reproducer is self-contained and the bug stays diagnosed
	// even if the production caller migrates. If this test ever
	// "fails to fail" against the new shape, it means the test data
	// no longer reproduces the bug — investigate, don't loosen.
	store := blobs{}
	bigJunk := strings.Repeat("/* node_modules junk */ ", 4096)
	bigBytes, bigDigest := makeTarGz(t, map[string]string{
		"node_modules/react/index.js": bigJunk,
		"importmap.json":              `{"imports":{"WRONG":"BIG"}}`,
	})
	store[bigDigest] = bigBytes
	smallBody := `{"imports":{"CORRECT":"SMALL"}}`
	smallBytes, smallDigest := makeTarGz(t, map[string]string{"importmap.json": smallBody})
	store[smallDigest] = smallBytes

	layers := []ImportmapLayer{
		layer("application/vnd.oci.image.layer.v1.tar+gzip", bigDigest, len(bigBytes)),
		layer("application/vnd.oci.image.layer.v1.tar+gzip", smallDigest, len(smallBytes)),
	}

	// Simulate the OLD algorithm: "iterate, break on first tar+gzip".
	var picked ImportmapLayer
	for _, l := range layers {
		if l.MediaType == "application/vnd.oci.image.layer.v1.tar+gzip" {
			picked = l
			break
		}
	}
	if picked.Digest != bigDigest {
		t.Fatalf("test scaffolding broke: old algorithm should pick big layer")
	}
	got, err := readImportmap(context.Background(), picked, store.fetcher())
	if err != nil {
		t.Fatalf("unexpected error in old-algo replay: %v", err)
	}
	if !strings.Contains(got, "WRONG") {
		t.Fatalf("old algorithm should yield the WRONG importmap; got: %s", got)
	}
	// Now the corrected algorithm picks the right one.
	got, err = FindImportmapInLayers(context.Background(), layers, store.fetcher())
	if err != nil {
		t.Fatalf("unexpected error in corrected algorithm: %v", err)
	}
	if got != smallBody {
		t.Errorf("corrected algorithm picked wrong layer.\n got:  %s\nwant: %s", got, smallBody)
	}
}

func TestFindImportmapInLayers_NoCandidates_Errors(t *testing.T) {
	// Manifest with no matching mediaTypes at all.
	layers := []ImportmapLayer{
		layer("application/vnd.oci.image.config.v1+json",
			digest.NewDigestFromHex("sha256", strings.Repeat("0", 64)), 100),
	}
	_, err := FindImportmapInLayers(context.Background(), layers, blobs{}.fetcher())
	if err == nil {
		t.Fatal("expected an error when no candidate layers are present")
	}
	if !strings.Contains(err.Error(), "no candidate importmap layer found") {
		t.Errorf("expected 'no candidate' error, got: %v", err)
	}
}

func TestFindImportmapInLayers_AllTarGzipMissingImportmap_Errors(t *testing.T) {
	// Multiple tar+gzip layers, none contain importmap.json.
	// Surface a clear error that names the last attempt rather than
	// silently returning empty content.
	store := blobs{}
	junkA, dgA := makeTarGz(t, map[string]string{"node_modules/a.js": "x"})
	store[dgA] = junkA
	junkB, dgB := makeTarGz(t, map[string]string{"node_modules/b.js": "y"})
	store[dgB] = junkB

	layers := []ImportmapLayer{
		layer("application/vnd.oci.image.layer.v1.tar+gzip", dgA, len(junkA)),
		layer("application/vnd.oci.image.layer.v1.tar+gzip", dgB, len(junkB)),
	}
	_, err := FindImportmapInLayers(context.Background(), layers, store.fetcher())
	if err == nil {
		t.Fatal("expected an error when no tar+gzip layer holds importmap.json")
	}
	if !strings.Contains(err.Error(), "no tar+gzip layer contained importmap.json") {
		t.Errorf("expected 'no tar+gzip layer' error, got: %v", err)
	}
}

func TestFindImportmapInLayers_FirstTarGzipMissingImportmap_FallsThroughToSecond(t *testing.T) {
	// Sort by size puts the smaller layer first. If it happens to
	// NOT contain importmap.json (defensive: future packager shapes,
	// non-standard images), fall through to the next candidate
	// rather than failing the whole call.
	store := blobs{}
	smallFiles := map[string]string{"node_modules/tiny.js": "ok"}
	smallBytes, smallDigest := makeTarGz(t, smallFiles)
	store[smallDigest] = smallBytes

	wantBody := `{"imports":{"react":"/-/modules/react/index.js"}}`
	bigJunk := strings.Repeat("/* padding */ ", 200)
	bigBytes, bigDigest := makeTarGz(t, map[string]string{
		"node_modules/a.js": bigJunk,
		"importmap.json":    wantBody,
	})
	store[bigDigest] = bigBytes

	layers := []ImportmapLayer{
		layer("application/vnd.oci.image.layer.v1.tar+gzip", smallDigest, len(smallBytes)),
		layer("application/vnd.oci.image.layer.v1.tar+gzip", bigDigest, len(bigBytes)),
	}
	got, err := FindImportmapInLayers(context.Background(), layers, store.fetcher())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantBody {
		t.Errorf("expected fallback to second layer.\n got:  %s\nwant: %s", got, wantBody)
	}
}
