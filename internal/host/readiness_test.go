package host

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func setHostCondition(hh *HostHandler, condition kdexv1alpha1.ConditionType) {
	status := &kdexv1alpha1.KDexObjectStatus{}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: string(condition), Status: metav1.ConditionTrue, Reason: "Test",
	})
	hh.mu.Lock()
	hh.status = status
	hh.mu.Unlock()
}

// A starting pod is held out of its Service until its host has loaded, so a
// rolling update no longer sends traffic to a pod that 404s every route.
func TestReadinessCheck_WaitsForTheHostToLoad(t *testing.T) {
	start := time.Unix(1_000, 0)
	clock := start
	now := func() time.Time { return clock }

	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.mu.Lock()
	hh.Mux = nil
	hh.mu.Unlock()
	check := hh.ReadinessCheck(start, 2*time.Minute, now)

	require.Error(t, check(nil), "no mux yet: not ready")

	hh = renderHost(t, nil)
	check = hh.ReadinessCheck(start, 2*time.Minute, now)
	require.Error(t, check(nil), "a mux but no settled reconcile (Initializing): not ready")

	setHostCondition(hh, kdexv1alpha1.ConditionTypeProgressing)
	require.Error(t, check(nil), "Progressing: not ready")

	setHostCondition(hh, kdexv1alpha1.ConditionTypeReady)
	require.NoError(t, check(nil), "Ready: ready")

	setHostCondition(hh, kdexv1alpha1.ConditionTypeProgressing)
	assert.NoError(t, check(nil), "readiness latches: a later reconcile never pulls the endpoint")
}

func TestReadinessCheck_DegradedHostServes(t *testing.T) {
	hh := renderHost(t, nil)
	setHostCondition(hh, kdexv1alpha1.ConditionTypeDegraded)
	assert.NoError(t, hh.ReadinessCheck(time.Now(), time.Minute, nil)(nil))
}

// A host that never loads must not hold the rollout forever: past the
// timeout the pod is ready regardless (#290).
func TestReadinessCheck_TimeoutBoundsTheGate(t *testing.T) {
	start := time.Unix(1_000, 0)
	clock := start
	hh := renderHost(t, nil) // Initializing, and stays so
	check := hh.ReadinessCheck(start, 2*time.Minute, func() time.Time { return clock })

	clock = start.Add(119 * time.Second)
	require.Error(t, check(nil))

	clock = start.Add(2 * time.Minute)
	require.NoError(t, check(nil))

	clock = start // latched, whatever the clock says
	assert.NoError(t, check(nil))
}

func TestReadinessCheck_ZeroTimeoutDisablesTheGate(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	assert.NoError(t, hh.ReadinessCheck(time.Now(), 0, nil)(nil))
}
