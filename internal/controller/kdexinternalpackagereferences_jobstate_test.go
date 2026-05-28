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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// TestClassifyPackRefJob pins the fix for kdex-tech/host-manager#61.
// The IPR reconciler previously treated `job.Status.Failed == 1` as a
// terminal failure: it deleted the Job, marked the IPR Degraded, and
// never let BackoffLimit:3 retry. Worse, when `Failed >= 2` the
// hard-coded `== 1` check was skipped and the controller fell through
// to extracting `imageDigest` from a failed pod's termination message
// (typically `npm ERR! 404 not found`), writing that string into
// `Status.Attributes["image"]` and reporting Ready=True with a garbage
// image reference. The KDexFunction controller solved the same shape
// in #27 via isCodegenJobTerminal; this test pins the IPR-side
// classifier that follows the same pattern.
func TestClassifyPackRefJob(t *testing.T) {
	tests := []struct {
		name      string
		job       *batchv1.Job
		wantState packRefJobState
		wantMsg   string
	}{
		{
			name: "initial — Succeeded=0, Failed=0",
			job: &batchv1.Job{
				Status: batchv1.JobStatus{},
			},
			wantState: packRefJobInProgress,
		},
		{
			name: "transient first failure — Failed=1, JobFailed not yet flipped",
			job: &batchv1.Job{
				Status: batchv1.JobStatus{
					Failed: 1,
					Conditions: []batchv1.JobCondition{
						{Type: batchv1.JobFailed, Status: corev1.ConditionFalse, Reason: "PodFailed"},
					},
				},
			},
			// Pre-fix this was treated as terminal. The whole point of
			// BackoffLimit:3 is to absorb exactly this case.
			wantState: packRefJobInProgress,
		},
		{
			name: "mid-retry — Failed=2, JobFailed still not flipped",
			job: &batchv1.Job{
				Status: batchv1.JobStatus{
					Failed: 2,
				},
			},
			wantState: packRefJobInProgress,
		},
		{
			name: "BackoffLimit exhausted — JobFailed=True",
			job: &batchv1.Job{
				Status: batchv1.JobStatus{
					Failed: 3,
					Conditions: []batchv1.JobCondition{
						{
							Type:    batchv1.JobFailed,
							Status:  corev1.ConditionTrue,
							Reason:  "BackoffLimitExceeded",
							Message: "Job has reached the specified backoff limit",
						},
					},
				},
			},
			wantState: packRefJobTerminalFailed,
			wantMsg:   "BackoffLimitExceeded: Job has reached the specified backoff limit",
		},
		{
			name: "deadline exceeded — JobFailed=True with deadline reason",
			job: &batchv1.Job{
				Status: batchv1.JobStatus{
					Conditions: []batchv1.JobCondition{
						{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"},
					},
				},
			},
			wantState: packRefJobTerminalFailed,
		},
		{
			name: "succeeded",
			job: &batchv1.Job{
				Status: batchv1.JobStatus{
					Succeeded: 1,
				},
			},
			wantState: packRefJobSucceeded,
		},
		{
			name: "succeeded after a transient failure (mixed state)",
			job: &batchv1.Job{
				Status: batchv1.JobStatus{
					Succeeded: 1,
					Failed:    1,
				},
			},
			wantState: packRefJobSucceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotState, gotMsg := classifyPackRefJob(tt.job)
			assert.Equal(t, tt.wantState, gotState, "state classification (#61)")
			if tt.wantMsg != "" {
				assert.Contains(t, gotMsg, tt.wantMsg, "terminal message should carry reason+message")
			}
		})
	}
}
