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
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

// VersionMismatch records one package whose installed version in a built
// packages image disagrees with the version pinned in the KIPR spec.
type VersionMismatch struct {
	Package string
	Want    string
	Got     string // "" when the package is absent from the image entirely
}

func (m VersionMismatch) String() string {
	if m.Got == "" {
		return fmt.Sprintf("%s@%s (absent from image)", m.Package, m.Want)
	}
	return fmt.Sprintf("%s pinned %s but image has %s", m.Package, m.Want, m.Got)
}

// VerifyPinnedVersions checks that a freshly built packages image actually
// contains the versions the KIPR pinned.
//
// This is the post-build half of kdex-tech/host-manager#161. During GitLab's
// post-publish npm propagation window the aggregation can retain a package's
// PREVIOUS bytes instead of failing, so packages:N ships stale modules under a
// correct pin — indistinguishable from success in the logs, and frozen there
// because the KIPR won't rebuild for an unchanged generation.
//
// Scope, deliberately: this compares the version each package DECLARES in its
// installed package.json against the pin. It is not a content check. The
// registry's dist.shasum covers a tarball, and the image holds an extracted
// tree, so the two are not comparable here — a tarball-integrity check has to
// happen where the fetch happens (node-tools' get_modules step; see #161).
// This catches the reported symptom — the previous VERSION baked into
// packages:N — and nothing weaker.
//
// Returns the mismatches found. An empty slice means every pin was satisfied.
// Pins with a non-exact version (ranges like "^1.2.0", tags, URLs) are skipped:
// the pinned string is not a version to compare against, and the packager is
// free to resolve it however npm would.
func VerifyPinnedVersions(
	ctx context.Context,
	layers []ImportmapLayer,
	pins map[string]string,
	fetch LayerFetcher,
) ([]VersionMismatch, error) {
	exact := make(map[string]string, len(pins))
	for name, version := range pins {
		if isExactVersion(version) {
			exact[name] = version
		}
	}
	if len(exact) == 0 {
		return nil, nil
	}

	// node_modules lives in the big layer, so search tar+gzip layers LARGEST
	// first — the mirror of FindImportmapInLayers, which wants the tiny
	// dedicated importmap layer. Stop as soon as every pin has been seen.
	candidates := make([]ImportmapLayer, 0, len(layers))
	for _, l := range layers {
		if l.MediaType == "application/vnd.oci.image.layer.v1.tar+gzip" {
			candidates = append(candidates, l)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Size > candidates[j].Size
	})

	found := make(map[string]string, len(exact))
	for _, l := range candidates {
		if err := collectInstalledVersions(ctx, l, exact, found, fetch); err != nil {
			return nil, err
		}
		if len(found) == len(exact) {
			break
		}
	}

	// No layer yielded a single top-level package.json. That is a shape this
	// function does not understand rather than evidence of stale bytes, and
	// reporting every pin as absent would fail every build. Say so instead.
	if len(found) == 0 {
		return nil, fmt.Errorf("no node_modules package.json found in any layer; cannot verify pinned versions")
	}

	mismatches := make([]VersionMismatch, 0)
	for name, want := range exact {
		got, ok := found[name]
		if !ok {
			// Seen SOME packages but not this one. Absent from a tree we could
			// otherwise read is a real finding.
			mismatches = append(mismatches, VersionMismatch{Package: name, Want: want})
			continue
		}
		if got != want {
			mismatches = append(mismatches, VersionMismatch{Package: name, Want: want, Got: got})
		}
	}
	sort.Slice(mismatches, func(i, j int) bool { return mismatches[i].Package < mismatches[j].Package })
	return mismatches, nil
}

// collectInstalledVersions streams one tar+gzip layer, recording the declared
// version of every wanted top-level package it encounters.
func collectInstalledVersions(
	ctx context.Context,
	layer ImportmapLayer,
	wanted map[string]string,
	into map[string]string,
	fetch LayerFetcher,
) error {
	rc, err := fetch(ctx, layer)
	if err != nil {
		return fmt.Errorf("fetch layer %s: %w", layer.Digest, err)
	}
	defer func() { _ = rc.Close() }()

	gr, err := gzip.NewReader(rc)
	if err != nil {
		// Not a readable gzip layer — skip it rather than fail the build.
		return nil
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry in %s: %w", layer.Digest, err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		name := topLevelPackageName(header.Name)
		if name == "" {
			continue
		}
		if _, want := wanted[name]; !want {
			continue
		}
		if _, seen := into[name]; seen {
			continue
		}

		var pj struct {
			Version string `json:"version"`
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("read %s from %s: %w", header.Name, layer.Digest, err)
		}
		if err := json.Unmarshal(data, &pj); err != nil {
			// A malformed package.json is not a version disagreement; leave
			// the package unrecorded so it surfaces as absent.
			continue
		}
		if pj.Version != "" {
			into[name] = pj.Version
		}
	}
}

// topLevelPackageName returns the package name for a tar entry that is a
// TOP-LEVEL node_modules package.json, or "" for anything else.
//
// Transitive dependencies (".../node_modules/a/node_modules/b/package.json")
// are excluded on purpose: only the packages the KIPR pinned are being
// verified, and a nested copy of a pinned name is a different install.
func topLevelPackageName(entry string) string {
	clean := path.Clean(strings.TrimPrefix(entry, "./"))
	if !strings.HasSuffix(clean, "/package.json") {
		return ""
	}

	idx := strings.Index(clean, "node_modules/")
	if idx < 0 {
		return ""
	}
	rest := clean[idx+len("node_modules/"):]

	// Anything with a further node_modules segment is transitive.
	if strings.Contains(rest, "node_modules/") {
		return ""
	}

	name := strings.TrimSuffix(rest, "/package.json")
	if name == "" || name == "package.json" {
		return ""
	}

	segments := strings.Split(name, "/")
	switch {
	case strings.HasPrefix(name, "@"):
		// Scoped: exactly @scope/name.
		if len(segments) != 2 {
			return ""
		}
	default:
		if len(segments) != 1 {
			return ""
		}
	}
	return name
}

// exactVersionRe matches a fully-qualified semver: all three numeric parts
// present, with an optional prerelease/build suffix.
//
// Deliberately strict. A partial version is still a RANGE in npm ("1.x" and
// "1.0" both match many releases), so anything short of major.minor.patch has
// no single version to compare against and must be skipped rather than
// compared — comparing it would fail legitimate builds.
var exactVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$`)

// isExactVersion reports whether a pin names one specific version, so that
// comparing it to an installed version is meaningful. Ranges, dist-tags, and
// URL/git specifiers are not comparable and are left alone.
func isExactVersion(version string) bool {
	return exactVersionRe.MatchString(strings.TrimSpace(version))
}
