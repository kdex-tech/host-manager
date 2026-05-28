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

	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestBuildUtilityPagePageHandler_PropagatesStatus pins the fix for
// kdex-tech/host-manager#55: the kdexpage controller passes
// `Status: &page.Status` into the PageHandler so PageHandler.Checksum
// folds the referenced-resource generations recorded in
// Status.Attributes into the render-cache key. The utility-page
// controller omitted that field, so every utility page's CacheKey
// collapsed to "<name>::<lang>" and never invalidated when theme,
// header, footer, app, navigation, or script-library inputs changed.
//
// The parallel TestPageHandler_Checksum_StatusNilCollapsesKey in
// internal/page/checksum_test.go pins the general contract; this test
// pins that the utility-page controller's own constructor
// (buildUtilityPagePageHandler) wires Status into the PageHandler it
// hands to HostHandler.
func TestBuildUtilityPagePageHandler_PropagatesStatus(t *testing.T) {
	iup := &kdexv1alpha1.KDexInternalUtilityPage{
		ObjectMeta: metav1.ObjectMeta{Name: "404", Generation: 7},
		Spec: kdexv1alpha1.KDexInternalUtilityPageSpec{
			KDexUtilityPageSpec: kdexv1alpha1.KDexUtilityPageSpec{
				Type: kdexv1alpha1.ErrorUtilityPageType,
			},
		},
		Status: kdexv1alpha1.KDexObjectStatus{
			ObservedGeneration: 7,
			Attributes: map[string]string{
				"archetype.generation":       "3",
				"archetype.header.generation": "2",
				"archetype.footer.generation": "1",
			},
		},
	}

	ph := buildUtilityPagePageHandler(
		iup,
		"<html><body>{{ .ErrorMessage }}</body></html>",
		map[string]page.PackedContent{}, "", "",
		map[string]string{},
		nil, nil, nil,
	)

	assert.NotNil(t, ph.Status,
		"PageHandler.Status must be wired from the controller so Checksum can mix in Status.Attributes (#55)")
	assert.NotEmpty(t, ph.Checksum(),
		"With Status set, Checksum must be non-empty so CacheKey contains entropy from referenced-resource generations")

	baseline := ph.CacheKey(language.English)

	// Bump a reference generation — simulates the operator editing the
	// referenced KDexPageHeader, whose controller writes the new gen
	// into Status.Attributes["archetype.header.generation"]. The cache
	// key must shift.
	iup.Status.Attributes["archetype.header.generation"] = "999"
	ph2 := buildUtilityPagePageHandler(
		iup,
		"<html><body>{{ .ErrorMessage }}</body></html>",
		map[string]page.PackedContent{}, "", "",
		map[string]string{},
		nil, nil, nil,
	)
	assert.NotEqual(t, baseline, ph2.CacheKey(language.English),
		"changing Status.Attributes must invalidate the utility-page cache key (#55)")
}
