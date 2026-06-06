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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestPackagesPendingOutcome_DoesNotGateAndReusesLastKnownImage pins the
// in-repo decouple slice of kdex-tech/host-manager#117. When the front-end
// packages image is (re)building or has failed, the host reconcile must NOT
// skip backend function route registration. packagesPendingOutcome encodes
// that: it surfaces the situation on the dedicated PackagesReady condition,
// reuses the last-known packages image/importmap so the existing packages route
// isn't disrupted, and returns a soft requeue — never a gate.
func TestPackagesPendingOutcome_DoesNotGateAndReusesLastKnownImage(t *testing.T) {
	r := &KDexInternalHostReconciler{RequeueDelay: 7 * time.Second}

	host := &kdexv1alpha1.KDexInternalHost{}
	host.Status.Attributes = map[string]string{
		"packages.image":     "reg.example.com/rsi-dev/packages:3@sha256:cafe",
		"packages.importmap": `{"imports":{"x":"/y"}}`,
	}

	backend, importMap, requeue := r.packagesPendingOutcome(host, "Building", "package image not available yet")

	require.NotNil(t, backend, "must reuse the last-known packages backend so its route isn't dropped mid-rebuild")
	assert.Equal(t, "reg.example.com/rsi-dev/packages:3@sha256:cafe", backend.Backend.StaticImage)
	assert.Equal(t, `{"imports":{"x":"/y"}}`, importMap, "must reuse the last-known importmap")
	assert.Equal(t, 7*time.Second, requeue.RequeueAfter, "must request a soft requeue for the pending build")

	cond := meta.FindStatusCondition(host.Status.Conditions, ConditionTypePackagesReady)
	require.NotNil(t, cond, "front-end package state must be surfaced on its own PackagesReady condition (#117)")
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
}

// TestPackagesPendingOutcome_FirstBuildNoLastImage covers the first-ever build:
// with no last-known image there's simply no packages backend yet, but the
// outcome still does not gate (returns a requeue + PackagesReady=False) so
// functions are unaffected.
func TestPackagesPendingOutcome_FirstBuildNoLastImage(t *testing.T) {
	r := &KDexInternalHostReconciler{RequeueDelay: 5 * time.Second}

	host := &kdexv1alpha1.KDexInternalHost{}
	host.Status.Attributes = map[string]string{}

	backend, importMap, requeue := r.packagesPendingOutcome(host, "Building", "building")

	assert.Nil(t, backend, "no last-known image => no packages backend yet")
	assert.Equal(t, "", importMap)
	assert.Equal(t, 5*time.Second, requeue.RequeueAfter)

	cond := meta.FindStatusCondition(host.Status.Conditions, ConditionTypePackagesReady)
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
}

// TestSetPackagesReadyCondition covers the dedicated condition helper toggling
// between Ready and not-Ready.
func TestSetPackagesReadyCondition(t *testing.T) {
	var conditions []metav1.Condition

	setPackagesReadyCondition(&conditions, metav1.ConditionTrue, "Available", "ok")
	cond := meta.FindStatusCondition(conditions, ConditionTypePackagesReady)
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, "Available", cond.Reason)

	setPackagesReadyCondition(&conditions, metav1.ConditionFalse, "BuildFailed", "boom")
	cond = meta.FindStatusCondition(conditions, ConditionTypePackagesReady)
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
	assert.Equal(t, "BuildFailed", cond.Reason)
}
