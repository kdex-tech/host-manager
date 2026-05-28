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
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestKDexInternalTranslation_DeletionDoesNotReAddTranslation pins the
// fix for kdex-tech/host-manager#53: the deletion branch in
// KDexInternalTranslationReconciler.Reconcile removed the in-memory
// translation and the finalizer, then fell through to the "reconciling"
// path and called AddOrUpdateTranslation on the very translation it had
// just deleted. The CR was GC'd by the API server (finalizer gone) but
// host-manager continued to serve the translation in-memory until pod
// restart.
func TestKDexInternalTranslation_DeletionDoesNotReAddTranslation(t *testing.T) {
	const (
		focalHost   = "test-host"
		namespace   = "default"
		crName      = "spanish"
		removedLang = "es"
	)

	scheme := runtime.NewScheme()
	assert.NoError(t, kdexv1alpha1.AddToScheme(scheme))
	assert.NoError(t, corev1.AddToScheme(scheme))

	cm, err := cache.NewCacheManager("", "", nil)
	assert.NoError(t, err)
	hh := host.NewHostHandler(nil, focalHost, namespace, logr.Discard(), cm)

	// Translations only compile into the catalog when host is set, since
	// RebuildMux short-circuits on a nil host. SetHost with a minimal
	// KDexHostSpec gets the catalog wired up.
	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en"},
		nil, nil, nil, nil, "", nil, nil,
		&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
	)

	trSpec := kdexv1alpha1.KDexTranslationSpec{
		Translations: []kdexv1alpha1.Translation{{
			Lang:          removedLang,
			KeysAndValues: map[string]string{"hello": "hola"},
		}},
	}

	// Seed the HostHandler with the translation so we can observe whether
	// the reconciler actually removes it.
	hh.AddOrUpdateTranslation(crName, &trSpec)
	assert.True(t, hasLanguage(hh, removedLang),
		"pre-condition: translation should be present in HostHandler")

	// Construct the CR in a "Deleting + finalizer present" state — exactly
	// what controller-runtime delivers between finalizer-add and final GC.
	now := metav1.NewTime(time.Now())
	cr := &kdexv1alpha1.KDexInternalTranslation{
		ObjectMeta: metav1.ObjectMeta{
			Name:              crName,
			Namespace:         namespace,
			DeletionTimestamp: &now,
			Finalizers:        []string{internal.TRANSLATION_FINALIZER},
		},
		Spec: kdexv1alpha1.KDexInternalTranslationSpec{
			KDexTranslationSpec: trSpec,
			HostRef:             corev1.LocalObjectReference{Name: focalHost},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	r := &KDexInternalTranslationReconciler{
		Client:              cl,
		ControllerNamespace: namespace,
		FocalHost:           focalHost,
		HostHandler:         hh,
		RequeueDelay:        50 * time.Millisecond,
		Scheme:              scheme,
	}

	// Reconcile may return an error from the deferred Status().Update on
	// a now-deleted CR (the fake client GC's it once the finalizer is
	// removed) — that's a separate concern; the assertion that matters
	// is whether the translation was re-added to the HostHandler.
	_, _ = r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: crName, Namespace: namespace},
	})

	assert.False(t, hasLanguage(hh, removedLang),
		"deletion-path reconcile must NOT re-add the translation it just removed (#53)")
}

// hasLanguage returns true if the HostHandler's compiled Translations
// catalog includes the given BCP-47 tag. After AddOrUpdateTranslation
// fires RebuildMux, the catalog is the publicly observable side effect.
func hasLanguage(hh *host.HostHandler, tag string) bool {
	for _, l := range hh.Translations.Languages() {
		if l.String() == tag {
			return true
		}
	}
	return false
}
