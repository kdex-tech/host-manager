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
	"testing"

	"github.com/stretchr/testify/assert"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// Regression for kdex-tech/host-manager#27. The previous `Failed == 1`
// short-circuit triggered on the first failed Pod and deleted-then-
// recreated the Job, never letting BackoffLimit (3) actually retire the
// Job into a terminal Failed state. The Kubernetes-level JobFailed
// condition is the authoritative signal — once it flips to True, the
// Job is done and the controller must surface that as Degraded without
// deleting the Job (the operator needs the pods around to inspect).
func TestIsCodegenJobTerminal(t *testing.T) {
	tests := []struct {
		name       string
		conditions []batchv1.JobCondition
		wantOK     bool
		wantMsgIn  string
	}{
		{
			name:       "no conditions: not terminal",
			conditions: nil,
			wantOK:     false,
		},
		{
			name: "Failed=False: not terminal (still retrying within BackoffLimit)",
			conditions: []batchv1.JobCondition{
				{Type: batchv1.JobFailed, Status: corev1.ConditionFalse, Reason: "PodFailed", Message: "transient"},
			},
			wantOK: false,
		},
		{
			name: "Failed=True with BackoffLimitExceeded: terminal",
			conditions: []batchv1.JobCondition{
				{
					Type:    batchv1.JobFailed,
					Status:  corev1.ConditionTrue,
					Reason:  "BackoffLimitExceeded",
					Message: "Job has reached the specified backoff limit",
				},
			},
			wantOK:    true,
			wantMsgIn: "BackoffLimitExceeded",
		},
		{
			name: "Complete=True alone: not terminal-Failed",
			conditions: []batchv1.JobCondition{
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
			},
			wantOK: false,
		},
		{
			name: "mixed: Complete True + Failed True (real apiservers won't emit this, defensive)",
			conditions: []batchv1.JobCondition{
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
				{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"},
			},
			wantOK:    true,
			wantMsgIn: "DeadlineExceeded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := &batchv1.Job{Status: batchv1.JobStatus{Conditions: tt.conditions}}
			gotOK, gotMsg := isCodegenJobTerminal(job)
			assert.Equal(t, tt.wantOK, gotOK)
			if tt.wantMsgIn != "" {
				assert.Contains(t, gotMsg, tt.wantMsgIn)
			}
		})
	}
}
