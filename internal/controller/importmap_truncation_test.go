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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Scenario 1 reproducer: Kubernetes terminationMessage truncation.
//
// Background: the auto-build importmap path used to read the
// generated JSON from the importmap-generator init container's
// /dev/termination-log. Kubernetes caps that file at 4096 bytes
// (TerminationMessageMaxLength); when the file is longer, kubelet
// stores only the TAIL — the first bytes are lost.
//
// The tests below pin that behaviour as observed in production and
// show the symptom (unparseable JSON, missing "imports" keyword).
// They do NOT propose a fix — the fix is to use a different
// transport (OCI artifact layer), which is what
// importmap_select_test.go validates.

// kubeletTerminationMessageMax mirrors the constant kubelet enforces
// when reading /dev/termination-log. As of v1.30+, the value lives
// at pkg/kubelet/kuberuntime/helpers.go's TerminationLogMaxLength,
// which is 4096. We hard-code it here because the kubelet package
// is not importable from outside the kubernetes/kubernetes module.
const kubeletTerminationMessageMax = 4096

// truncateAsKubelet returns the LAST N bytes of the input, matching
// the kubelet behaviour of trimming the head when the
// terminationMessage file exceeds the cap. (Reading
// kubernetes/pkg/kubelet/container/helpers.go:truncate as of the
// kubelet versions deployed on GKE 1.36: the implementation slices
// data[len(data)-maxBytes:] when oversized, preserving the tail.)
func truncateAsKubelet(s string) string {
	if len(s) <= kubeletTerminationMessageMax {
		return s
	}
	return s[len(s)-kubeletTerminationMessageMax:]
}

// makeRealisticImportmap builds an importmap JSON with `entries`
// bare-specifier→URL pairs plus a matching integrity block — the
// same shape the node-tools importmap_generator emits. Returns
// the formatted JSON string.
func makeRealisticImportmap(t *testing.T, entries int) string {
	t.Helper()
	type importmap struct {
		Imports   map[string]string `json:"imports"`
		Integrity map[string]string `json:"integrity"`
	}
	im := importmap{
		Imports:   make(map[string]string, entries),
		Integrity: make(map[string]string, entries),
	}
	// Mix realistic specifier shapes: short bares, scoped, deep subpaths.
	patterns := []string{
		"react/index.js",
		"react-dom/index.js",
		"react-dom/client.js",
		"react/jsx-runtime.js",
		"@kdex-tech/ui/dist/index.mjs",
		"@recourse-software/knowdrive-l10n/dist/index.js",
		"@recourse-software/knowdrive-landing/dist/index.js",
		"@recourse-software/knowdrive-workbench/dist/index.js",
		"i18next/dist/esm/i18next.js",
		"i18next-http-backend/esm/index.js",
		"i18next-http-backend/esm/request.js",
		"i18next-http-backend/esm/utils.js",
		"react-i18next/dist/es/index.js",
		"react-i18next/dist/es/useTranslation.js",
		"react-i18next/dist/es/Trans.js",
		"react-i18next/dist/es/Translation.js",
		"react-i18next/dist/es/TransWithoutContext.js",
		"react-i18next/dist/es/I18nextProvider.js",
		"react-i18next/dist/es/context.js",
		"react-i18next/dist/es/defaults.js",
		"react-i18next/dist/es/i18nInstance.js",
		"react-i18next/dist/es/initReactI18next.js",
		"react-i18next/dist/es/unescape.js",
		"react-i18next/dist/es/useSSR.js",
		"react-i18next/dist/es/utils.js",
		"react-i18next/dist/es/withSSR.js",
		"react-i18next/dist/es/withTranslation.js",
		"prop-types/index.js",
		"html-parse-stringify/dist/html-parse-stringify.module.js",
		"void-elements/index.js",
		"@stripe/stripe-js/dist/index.mjs",
		"@stripe/stripe-js/lib/index.mjs",
		"@stripe/react-stripe-js/dist/react-stripe.esm.mjs",
	}
	for i := 0; i < entries; i++ {
		key := patterns[i%len(patterns)]
		if i >= len(patterns) {
			key = fmt.Sprintf("%s?v=%d", key, i) // ensure unique
		}
		url := "/-/modules/" + key
		im.Imports[key] = url
		// Production hashes are sha384 (48 bytes); fake sha256 is fine here.
		h := sha256.Sum256([]byte(key))
		im.Integrity[url] = "sha384-" + hex.EncodeToString(h[:])
	}
	out, err := json.MarshalIndent(im, "", "  ")
	if err != nil {
		t.Fatalf("marshal importmap: %v", err)
	}
	return string(out)
}

func TestTerminationMessage_Truncation_BreaksLargeImportmap(t *testing.T) {
	// 30 entries plus matching integrity hashes lands solidly above
	// the 4 KiB cap (current production importmaps run ~7 KiB).
	full := makeRealisticImportmap(t, 30)
	if len(full) <= kubeletTerminationMessageMax {
		t.Fatalf("test setup: importmap too small to reproduce truncation (got %d bytes, need >%d)",
			len(full), kubeletTerminationMessageMax)
	}

	truncated := truncateAsKubelet(full)
	if len(truncated) != kubeletTerminationMessageMax {
		t.Fatalf("truncation produced unexpected length: got %d, want %d", len(truncated), kubeletTerminationMessageMax)
	}

	// Symptom 1: the truncated payload is no longer valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(truncated), &parsed); err == nil {
		t.Errorf("truncated importmap parsed without error — expected failure since the head '{ \"imports\": {' is gone")
	}

	// Symptom 2: the leading "imports" keyword is absent from what
	// the kubelet writes back to the container status. Production
	// browsers see this and cannot resolve any bare specifier.
	if strings.Contains(truncated, `"imports"`) {
		t.Errorf("expected the 'imports' key to be lost to head truncation; still present in tail")
	}

	// Symptom 3: the truncated payload starts mid-string (mid-base64
	// fragment of some integrity hash) — exact pattern dev.knowdrive.ai
	// reproduced before the v0.2.62 attempt at a fix.
	if strings.HasPrefix(strings.TrimSpace(truncated), "{") {
		t.Errorf("expected truncated payload to start mid-string, not with '{'")
	}
}

func TestTerminationMessage_Truncation_PreservesSmallImportmap(t *testing.T) {
	// Conversely, a small importmap fits cleanly under the cap and
	// survives unchanged — this is why the bug was latent for so long.
	full := makeRealisticImportmap(t, 5)
	if len(full) > kubeletTerminationMessageMax {
		t.Fatalf("test setup: 5-entry importmap unexpectedly large (%d bytes)", len(full))
	}

	truncated := truncateAsKubelet(full)
	if truncated != full {
		t.Fatalf("small importmap was unexpectedly truncated")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(truncated), &parsed); err != nil {
		t.Fatalf("small importmap should parse cleanly: %v", err)
	}
	if _, ok := parsed["imports"]; !ok {
		t.Errorf("expected the small importmap to preserve the 'imports' key")
	}
}

func TestTerminationMessage_Truncation_BoundaryAtCap(t *testing.T) {
	// At exactly 4096 bytes, no truncation. At 4097 bytes, the
	// payload loses its first byte. This boundary check pins the
	// off-by-one nature of the cap.
	atCap := strings.Repeat("a", kubeletTerminationMessageMax)
	if truncateAsKubelet(atCap) != atCap {
		t.Errorf("payload at exactly 4096 bytes should be unmodified")
	}
	overByOne := "X" + strings.Repeat("a", kubeletTerminationMessageMax)
	got := truncateAsKubelet(overByOne)
	if len(got) != kubeletTerminationMessageMax {
		t.Errorf("over-by-one payload should be cut to 4096 bytes, got %d", len(got))
	}
	if strings.HasPrefix(got, "X") {
		t.Errorf("first byte should be lost to head truncation; still present")
	}
	if got != strings.Repeat("a", kubeletTerminationMessageMax) {
		t.Errorf("payload tail should be preserved verbatim")
	}
}
