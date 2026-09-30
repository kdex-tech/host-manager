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

	"github.com/kdex-tech/host-manager/internal/host"
)

// TestFormatRouteCollisions pins the Degraded(RouteCollision) message for a
// page-vs-page collision (unchanged) and for a refused KDexFunction route,
// whose conflicting route is either a tracked page/function or an untracked
// built-in route.
func TestFormatRouteCollisions(t *testing.T) {
	got := formatRouteCollisions([]host.RouteCollision{
		{Pattern: "GET /fr/{$}", WinnerName: "home", WinnerBasePath: "/", LoserName: "fr-page", LoserBasePath: "/fr"},
		{Pattern: "/x/v1/", ConflictingPattern: "GET /x/{path...}", WinnerName: "catchall", WinnerBasePath: "/x", LoserName: "KDexFunction/api", LoserBasePath: "/x/v1"},
		{Pattern: "/api", ConflictingPattern: "/api", WinnerName: "KDexFunction/a", WinnerBasePath: "/api", LoserName: "KDexFunction/b", LoserBasePath: "/api"},
		{Pattern: "/-/x", LoserName: "KDexFunction/sys", LoserBasePath: "/-/x"},
	})
	want := `4 route collision(s) detected; each refused route is unreachable for its loser: ` +
		`GET /fr/{$} claimed by page "home" (basePath "/"), refused for page "fr-page" (basePath "/fr"); ` +
		`/x/v1/ conflicts with GET /x/{path...} claimed by page "catchall" (basePath "/x"), refused for function "api" (basePath "/x/v1"); ` +
		`/api conflicts with /api claimed by function "a" (basePath "/api"), refused for function "b" (basePath "/api"); ` +
		`/-/x conflicts with an existing route, refused for function "sys" (basePath "/-/x")`
	if got != want {
		t.Fatalf("formatRouteCollisions:\n got: %s\nwant: %s", got, want)
	}
}
