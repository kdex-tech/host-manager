/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package packref

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"

	"github.com/kdex-tech/host-manager/internal"
)

// kdex-tech/host-manager#182: with no CacheClaim the packager Job gets only an
// ephemeral EmptyDir and no NPM_CONFIG_CACHE, so node-tools' verification
// ledger resolves to null and is disabled outright. Every dependency then takes
// the full fetch/gunzip/tar-parse path on every run — measured at 54.21s of a
// 61.26s prod container, 88%, sustained across 33 generations.
//
// The mounting code is correct and has been all along; the claim was simply
// never configured, and nothing said so. These pin the announcement, because a
// silent 15x cost is the part that let it run for 33 generations.

func captureLogs(sink *strings.Builder) logr.Logger {
	return funcr.New(func(prefix, args string) {
		sink.WriteString(args)
		sink.WriteString("\n")
	}, funcr.Options{})
}

func newCachePackRef(t *testing.T, cacheClaim string, sink *strings.Builder) *PackRef {
	t.Helper()
	p := newIdempotentPackRef(t, idempotentTestScheme(t))
	p.Packages.CacheClaim = cacheClaim
	p.Log = captureLogs(sink)
	return p
}

func newIPR() *kdexv1alpha1.KDexInternalPackageReferences {
	return &kdexv1alpha1.KDexInternalPackageReferences{
		ObjectMeta: metav1.ObjectMeta{Name: "ipr", Namespace: "dev", Generation: 1, UID: "u-ipr"},
	}
}

func TestPackagerJobWithoutCacheClaimSaysSo(t *testing.T) {
	var sink strings.Builder
	p := newCachePackRef(t, "", &sink)

	job, err := p.GetOrCreatePackRefJob(context.Background(), newIPR())
	require.NoError(t, err)
	require.NotNil(t, job)

	logged := sink.String()
	assert.Contains(t, logged, "cacheClaim",
		"the disabled state must name the setting that turns it on")
	assert.Contains(t, strings.ToLower(logged), "verification ledger",
		"and must say what is actually degraded, not just that a cache is absent")
}

// The warning must not fire when a claim IS configured, or it becomes noise
// that the next reader learns to ignore.
func TestPackagerJobWithCacheClaimIsQuiet(t *testing.T) {
	var sink strings.Builder
	p := newCachePackRef(t, "packages-cache", &sink)

	job, err := p.GetOrCreatePackRefJob(context.Background(), newIPR())
	require.NoError(t, err)
	require.NotNil(t, job)

	assert.NotContains(t, strings.ToLower(sink.String()), "verification ledger")
}

// The behaviour the warning describes: a configured claim really is mounted and
// really is advertised through the env node-tools reads.
func TestCacheClaimIsMountedAndAdvertised(t *testing.T) {
	var sink strings.Builder
	p := newCachePackRef(t, "packages-cache", &sink)

	job, err := p.GetOrCreatePackRefJob(context.Background(), newIPR())
	require.NoError(t, err)
	require.NotNil(t, job)

	var claim string
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			claim = v.PersistentVolumeClaim.ClaimName
		}
	}
	assert.Equal(t, "packages-cache", claim, "the claim must be mounted, not just referenced")

	var npmBuild *corev1.Container
	for i := range job.Spec.Template.Spec.InitContainers {
		if job.Spec.Template.Spec.InitContainers[i].Name == "npm-build" {
			npmBuild = &job.Spec.Template.Spec.InitContainers[i]
		}
	}
	require.NotNil(t, npmBuild, "packager Job must have an npm-build container")

	env := map[string]string{}
	for _, e := range npmBuild.Env {
		env[e.Name] = e.Value
	}
	// resolveLedgerDir() reads NPM_CONFIG_CACHE's PARENT, so the ledger lands
	// beside the npm cache on the claim rather than inside it.
	assert.Equal(t, internal.CACHE_DIR+"/npm", env["NPM_CONFIG_CACHE"])
	assert.Equal(t, internal.CACHE_DIR+"/bun", env["BUN_INSTALL_CACHE_DIR"])

	var mounted bool
	for _, m := range npmBuild.VolumeMounts {
		if m.MountPath == internal.CACHE_DIR {
			mounted = true
		}
	}
	assert.True(t, mounted, "the claim must be mounted into npm-build at "+internal.CACHE_DIR)
}
