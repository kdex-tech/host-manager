/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pkgJSON(name, version string) string {
	return fmt.Sprintf(`{"name":%q,"version":%q}`, name, version)
}

// nodeModulesLayer builds a node_modules tar+gzip layer holding one
// package.json per entry, keyed by package name.
func nodeModulesLayer(t *testing.T, installed map[string]string) (blobs, ImportmapLayer) {
	t.Helper()
	files := map[string]string{}
	for name, version := range installed {
		files["node_modules/"+name+"/package.json"] = pkgJSON(name, version)
	}
	data, dgst := makeTarGz(t, files)
	store := blobs{dgst: data}
	return store, layer(tarGzMediaType, dgst, len(data))
}

// TestVerifyPinnedVersions_CatchesPreviousVersionBytes is the core of
// kdex-tech/host-manager#161: a pin bumped to 0.1.6 whose built image still
// carries 0.1.5. The Job exits 0 and the logs read as success, so without this
// check the stale image is published and frozen (the KIPR won't rebuild for an
// unchanged generation).
func TestVerifyPinnedVersions_CatchesPreviousVersionBytes(t *testing.T) {
	store, l := nodeModulesLayer(t, map[string]string{
		"@kdex-tech/developer-keys": "0.1.5", // propagation window served the old one
		"react":                     "19.0.0",
	})

	mismatches, err := VerifyPinnedVersions(
		context.Background(),
		[]ImportmapLayer{l},
		map[string]string{
			"@kdex-tech/developer-keys": "0.1.6",
			"react":                     "19.0.0",
		},
		store.fetcher(),
	)
	require.NoError(t, err)
	require.Len(t, mismatches, 1, "only the lagged package should be reported")
	assert.Equal(t, "@kdex-tech/developer-keys", mismatches[0].Package)
	assert.Equal(t, "0.1.6", mismatches[0].Want)
	assert.Equal(t, "0.1.5", mismatches[0].Got)
	assert.Contains(t, mismatches[0].String(), "pinned 0.1.6 but image has 0.1.5")
}

// TestVerifyPinnedVersions_CleanBuildPasses is the control: when the image
// carries exactly what was pinned, nothing is reported. Without this a
// too-eager check would fail every build.
func TestVerifyPinnedVersions_CleanBuildPasses(t *testing.T) {
	store, l := nodeModulesLayer(t, map[string]string{
		"@kdex-tech/developer-keys": "0.1.6",
		"react":                     "19.0.0",
	})

	mismatches, err := VerifyPinnedVersions(
		context.Background(),
		[]ImportmapLayer{l},
		map[string]string{
			"@kdex-tech/developer-keys": "0.1.6",
			"react":                     "19.0.0",
		},
		store.fetcher(),
	)
	require.NoError(t, err)
	assert.Empty(t, mismatches)
}

// TestVerifyPinnedVersions_MissingPackageIsAMismatch covers the other shape of
// a silent bad build: the pin resolved to nothing at all, yet the aggregation
// still produced an image.
func TestVerifyPinnedVersions_MissingPackageIsAMismatch(t *testing.T) {
	store, l := nodeModulesLayer(t, map[string]string{"react": "19.0.0"})

	mismatches, err := VerifyPinnedVersions(
		context.Background(),
		[]ImportmapLayer{l},
		map[string]string{"react": "19.0.0", "@kdex-tech/developer-keys": "0.1.6"},
		store.fetcher(),
	)
	require.NoError(t, err)
	require.Len(t, mismatches, 1)
	assert.Equal(t, "@kdex-tech/developer-keys", mismatches[0].Package)
	assert.Empty(t, mismatches[0].Got)
	assert.Contains(t, mismatches[0].String(), "absent from image")
}

// TestVerifyPinnedVersions_IgnoresTransitiveCopies pins the tree-walk rule. A
// nested node_modules/<pinned-name> is a different install of that name, and
// letting it answer for the top-level pin would both mask a real mismatch and
// invent false ones.
func TestVerifyPinnedVersions_IgnoresTransitiveCopies(t *testing.T) {
	data, dgst := makeTarGz(t, map[string]string{
		"node_modules/react/package.json":                       pkgJSON("react", "19.0.0"),
		"node_modules/some-dep/node_modules/react/package.json": pkgJSON("react", "17.0.0"),
	})
	store := blobs{dgst: data}

	mismatches, err := VerifyPinnedVersions(
		context.Background(),
		[]ImportmapLayer{layer(tarGzMediaType, dgst, len(data))},
		map[string]string{"react": "19.0.0"},
		store.fetcher(),
	)
	require.NoError(t, err)
	assert.Empty(t, mismatches, "the nested 17.0.0 copy must not answer for the top-level pin")
}

// TestVerifyPinnedVersions_SkipsNonExactPins: a range/tag pin has no single
// version to compare, so it is left to npm. Failing those would break every
// host that pins with a caret.
func TestVerifyPinnedVersions_SkipsNonExactPins(t *testing.T) {
	store, l := nodeModulesLayer(t, map[string]string{
		"react":        "19.2.0", // legitimately resolved from ^19.0.0
		"pinned-exact": "1.0.0",
	})

	mismatches, err := VerifyPinnedVersions(
		context.Background(),
		[]ImportmapLayer{l},
		map[string]string{
			"react":        "^19.0.0",
			"pinned-exact": "1.0.0",
		},
		store.fetcher(),
	)
	require.NoError(t, err)
	assert.Empty(t, mismatches)
}

func TestIsExactVersion(t *testing.T) {
	for _, v := range []string{"1.0.0", "0.1.6", "2.3.4-rc.1"} {
		assert.True(t, isExactVersion(v), "%q is an exact version", v)
	}
	// Partial versions are RANGES in npm ("1.0" and "1.x" both match many
	// releases), so they have no single version to compare against.
	for _, v := range []string{"^1.0.0", "~1.0.0", ">=1.0.0", "1.x", "1.0", "1", "latest", "next", "*", "",
		"https://example.com/p.tgz", "npm:other@1.0.0", "file:../local", "1.0.0 - 2.0.0"} {
		assert.False(t, isExactVersion(v), "%q must not be treated as an exact version", v)
	}
}

// TestVerifyPinnedVersions_UnreadableImageIsNotAMismatch keeps "could not
// verify" distinct from "verified and wrong". Conflating them would reject good
// builds on a registry blip, which is a worse failure than the one being fixed.
func TestVerifyPinnedVersions_UnreadableImageIsNotAMismatch(t *testing.T) {
	data, dgst := makeTarGz(t, map[string]string{"unrelated/file.txt": "no packages here"})
	store := blobs{dgst: data}

	_, err := VerifyPinnedVersions(
		context.Background(),
		[]ImportmapLayer{layer(tarGzMediaType, dgst, len(data))},
		map[string]string{"react": "19.0.0"},
		store.fetcher(),
	)
	require.Error(t, err, "an image with no node_modules at all is unverifiable, not poisoned")
	assert.Contains(t, err.Error(), "cannot verify")
}

// TestVerifyPinnedVersions_SearchesLargestLayerFirst mirrors the importmap
// selection rule in reverse: node_modules lives in the big layer, so the small
// dedicated importmap layer must not end the search.
func TestVerifyPinnedVersions_SearchesLargestLayerFirst(t *testing.T) {
	bigData, bigDigest := makeTarGz(t, map[string]string{
		"node_modules/react/package.json": pkgJSON("react", "19.0.0"),
		"node_modules/react/index.js":     "// padding to make this the larger layer" + string(make([]byte, 4096)),
	})
	smallData, smallDigest := makeTarGz(t, map[string]string{
		"importmap.json": `{"imports":{"react":"/-/modules/react/index.js"}}`,
	})
	require.Greater(t, len(bigData), len(smallData), "fixture must have a genuinely larger node_modules layer")

	store := blobs{bigDigest: bigData, smallDigest: smallData}

	mismatches, err := VerifyPinnedVersions(
		context.Background(),
		[]ImportmapLayer{
			layer(tarGzMediaType, smallDigest, len(smallData)),
			layer(tarGzMediaType, bigDigest, len(bigData)),
		},
		map[string]string{"react": "19.0.0"},
		store.fetcher(),
	)
	require.NoError(t, err)
	assert.Empty(t, mismatches)
}

func TestTopLevelPackageName(t *testing.T) {
	for entry, want := range map[string]string{
		"node_modules/react/package.json":                       "react",
		"./node_modules/react/package.json":                     "react",
		"app/node_modules/@scope/name/package.json":             "@scope/name",
		"node_modules/some-dep/node_modules/react/package.json": "",
		"node_modules/react/dist/package.json":                  "",
		"node_modules/@scope/name/dist/package.json":            "",
		"package.json":                "",
		"node_modules/react/index.js": "",
	} {
		assert.Equal(t, want, topLevelPackageName(entry), "entry %q", entry)
	}
}
