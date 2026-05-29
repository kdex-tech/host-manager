/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeDeployerURL pins the fix for
// kdex-tech/host-manager#92. Pre-fix handleExecutableAvailable did
// `json.Unmarshal(msg, &res); Status.URL = res.URL` — an empty URL
// (`{"url":""}` from knative-deployer's not-yet-admitted case, or any
// deployer bug producing success-with-empty-URL) was silently
// accepted, the function transitioned to FunctionDeployed → Ready=True,
// the host-handler mounted a route at an empty upstream, and end
// users got 502 Bad Gateway with a healthy-looking CR.
//
// Post-fix decodeDeployerURL surfaces the empty URL as an error so
// the handler's error path runs (Degraded=True, delete job,
// requeue).
func TestDecodeDeployerURL(t *testing.T) {
	t.Run("valid URL is returned", func(t *testing.T) {
		got, err := decodeDeployerURL(`{"url":"https://fn.example.com/v1"}`)
		require.NoError(t, err)
		assert.Equal(t, "https://fn.example.com/v1", got)
	})

	t.Run("empty URL is rejected (#92)", func(t *testing.T) {
		_, err := decodeDeployerURL(`{"url":""}`)
		require.Error(t, err)
		assert.True(t,
			strings.Contains(strings.ToLower(err.Error()), "empty"),
			"empty-URL rejection should mention 'empty'; got %q", err.Error())
	})

	t.Run("missing URL key is rejected (#92)", func(t *testing.T) {
		_, err := decodeDeployerURL(`{}`)
		require.Error(t, err,
			"deployer returning {} (no url key) is structurally identical to {url:\"\"} and must be rejected")
	})

	t.Run("malformed JSON is rejected", func(t *testing.T) {
		_, err := decodeDeployerURL(`not json`)
		require.Error(t, err)
	})
}
