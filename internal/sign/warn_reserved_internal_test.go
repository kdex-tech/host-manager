package sign

import (
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/kdex-tech/dmapper"
	"github.com/stretchr/testify/assert"
)

// Mappers are rebuilt on every page change and host reconcile, so a stored rule
// targeting a reserved claim must be reported once per configuration, not on
// every rebuild; a different configuration is still reported.
func TestWarnReservedTargets_OncePerConfiguration(t *testing.T) {
	var lines int
	saved := signerLog
	signerLog = funcr.New(func(string, string) { lines++ }, funcr.Options{})
	t.Cleanup(func() { signerLog = saved })

	rules := []dmapper.MappingRule{{SourceExpression: `"x"`, TargetPropPath: "aud"}}
	for range 3 {
		WarnReservedTargets(rules, "function", "warn-once-a")
	}
	assert.Equal(t, 1, lines, "the same configuration is reported once")

	WarnReservedTargets(rules, "function", "warn-once-b")
	assert.Equal(t, 2, lines, "another configuration is still reported")

	WarnReservedTargets([]dmapper.MappingRule{{SourceExpression: `"x"`, TargetPropPath: "entitlements"}}, "function", "warn-once-c")
	assert.Equal(t, 2, lines, "a rule targeting no reserved claim is not reported")
}
