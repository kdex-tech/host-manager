/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package deploy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	batchv1 "k8s.io/api/batch/v1"
)

// TestDeployJob_ActiveDeadlineSecondsSet pins the fix for
// kdex-tech/host-manager#63: the deployer Job built by Deployer.Deploy
// must carry an ActiveDeadlineSeconds. Pre-fix only BackoffLimit was
// set; a pod that hangs forever (Knative API blocked, deployer probe
// stuck) never failed, so BackoffLimit never engaged and the Job sat
// Running indefinitely — silent stuck-Progressing for the KDexFunction.
func TestDeployJob_ActiveDeadlineSecondsSet(t *testing.T) {
	d, fn := scalingTestSetup(t)
	job, err := d.Deploy(context.Background(), fn)
	assert.NoError(t, err)

	assertJobHasReasonableDeadline(t, &job.Spec, "deployer")
}

func assertJobHasReasonableDeadline(t *testing.T, spec *batchv1.JobSpec, label string) {
	t.Helper()
	assert.NotNilf(t, spec.ActiveDeadlineSeconds,
		"%s Job must set ActiveDeadlineSeconds (#63) — otherwise a hung pod runs forever and BackoffLimit never fires", label)
	if spec.ActiveDeadlineSeconds == nil {
		return
	}
	assert.Greater(t, *spec.ActiveDeadlineSeconds, int64(0),
		"%s Job ActiveDeadlineSeconds must be > 0", label)
	assert.LessOrEqual(t, *spec.ActiveDeadlineSeconds, int64(2*60*60),
		"%s Job ActiveDeadlineSeconds should be aggressive (≤ 2h) — operator-friendly upper bound", label)
}

