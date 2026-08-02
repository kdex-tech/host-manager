/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

const filterTestHost = "rsi-dev"

// newKIPRForHost builds the KDexInternalPackageReferences exactly as
// handleInternalPackageReferences does: named after the HOST, with spec.hostRef
// pointing back at it. The "-packages" suffix belongs to the serving Deployment,
// never to this object — which is the whole point of #160.
func newKIPRForHost(name, hostRef string) *kdexv1alpha1.KDexInternalPackageReferences {
	kipr := &kdexv1alpha1.KDexInternalPackageReferences{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "dev"},
	}
	if hostRef != "" {
		kipr.Spec.HostRef = corev1.LocalObjectReference{Name: hostRef}
	}
	return kipr
}

// TestHasFocalHost_AcceptsPackageReferencesForThisHost pins
// kdex-tech/host-manager#160.
//
// hasFocalHost backs the controller-wide event filter, so a false drops the
// event for every source including Owns(&KDexInternalPackageReferences{}).
// Pre-fix the KIPR arm compared against "<host>-packages" — the DEPLOYMENT's
// name — while the KIPR is created as "<host>". Nothing ever matched, so the
// status.attributes.image write that promotes a freshly built packages:N was
// discarded and the Deployment kept serving N-1.
func TestHasFocalHost_AcceptsPackageReferencesForThisHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		obj  *kdexv1alpha1.KDexInternalPackageReferences
		want bool
	}{
		{
			// The real shape: named after the host, hostRef set.
			name: "KIPR for this host",
			obj:  newKIPRForHost(filterTestHost, filterTestHost),
			want: true,
		},
		{
			// Defensive: an older KIPR created before spec.hostRef was
			// populated must still be recognised by name alone, or #160
			// silently returns for those objects.
			name: "KIPR for this host with no hostRef",
			obj:  newKIPRForHost(filterTestHost, ""),
			want: true,
		},
		{
			// The filter's actual job: this controller instance serves one
			// host, so another host's KIPR must stay filtered out.
			name: "KIPR belonging to a different host",
			obj:  newKIPRForHost("rsi-prod", "rsi-prod"),
			want: false,
		},
		{
			// The pre-fix expectation, asserted as WRONG. "<host>-packages"
			// is the Deployment's name; no KIPR is ever created with it, so
			// treating it as this host's KIPR would re-introduce the
			// name-convention confusion that caused #160.
			name: "object named like the packages Deployment is not this host's KIPR",
			obj:  newKIPRForHost(filterTestHost+"-packages", ""),
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hasFocalHost(filterTestHost, tc.obj),
				"a dropped KIPR event means a built packages:N never reaches the Deployment (#160)")
		})
	}
}

// TestHasFocalHost_OtherKindsUnchanged guards the arms this fix did not touch.
// The filter narrows to one host; it is not a relevance test, so unlisted kinds
// must keep falling through to true rather than being silently dropped.
func TestHasFocalHost_OtherKindsUnchanged(t *testing.T) {
	host := &kdexv1alpha1.KDexInternalHost{ObjectMeta: metav1.ObjectMeta{Name: filterTestHost}}
	assert.True(t, hasFocalHost(filterTestHost, host))

	otherHost := &kdexv1alpha1.KDexInternalHost{ObjectMeta: metav1.ObjectMeta{Name: "rsi-prod"}}
	assert.False(t, hasFocalHost(filterTestHost, otherHost))

	page := &kdexv1alpha1.KDexPage{}
	page.Spec.HostRef = corev1.LocalObjectReference{Name: filterTestHost}
	assert.True(t, hasFocalHost(filterTestHost, page))

	otherPage := &kdexv1alpha1.KDexPage{}
	otherPage.Spec.HostRef = corev1.LocalObjectReference{Name: "rsi-prod"}
	assert.False(t, hasFocalHost(filterTestHost, otherPage))

	// Owned core types carry no host reference of their own — they reach the
	// reconciler via ownership, so the filter must not drop them.
	assert.True(t, hasFocalHost(filterTestHost,
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: filterTestHost + "-packages"}}),
		"the packages Deployment is matched by ownership, not by this filter")
}
