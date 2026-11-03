// Package projector replicates nexus-manager's user-facing-CR → Internal*-CR
// projection in-process, so kdex preview can consume a real cluster's CR set
// directly. Three projections are implemented matching nexus-manager source:
//
//	KDexHost         → KDexInternalHost          (kdexhost_controller.go:651-736)
//	KDexTranslation  → KDexInternalTranslation   (kdexhost_controller_util.go:36-112)
//	KDexUtilityPage  → KDexInternalUtilityPage   (kdexhost_controller_util.go:114-181)
//
// Projections are pure functions over CR specs — no API server, no controller
// runtime, no OwnerReferences (preview has no apiserver to attach to).
//
// Out of scope (documented limitations):
//   - kdex-default-translation auto-injection (per-host, in nexus-manager).
//     If your host references it, copy the kdex-default-translation CR into
//     your --crs directory.
//   - kdex-default-script-library (and similar cluster-level "default" CRs
//     installed by nexus-manager). If a page or archetype references one,
//     copy the cluster's actual default CR into your --crs directory or the
//     page reconciler will hard-fail with a NotFound error.
//   - Default utility-page short-circuit names (require webhook constants)
//   - CreationTimestamp-ordered archetype defaulting (Phase 3 task)
//   - kdex.dev/generation label (nexus-manager stamps the host's generation;
//     preview has no real generation tracking)
package projector

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// ProjectInput collects all CRs the host projection needs to look up.
// Translations and UtilityPages are walked to validate the host's *Ref fields;
// missing refs produce warnings, not errors.
type ProjectInput struct {
	UtilityPages []kdexv1alpha1.KDexUtilityPage
	Translations []kdexv1alpha1.KDexTranslation
}

// ProjectedHost bundles the resulting KDexInternalHost with non-fatal warnings
// emitted during projection. KDexInternalHost is embedded so callers can access
// Name, Namespace, Spec, etc. directly on the returned value.
type ProjectedHost struct {
	kdexv1alpha1.KDexInternalHost
	Warnings []string
}

// ProjectHost replicates nexus-manager's createOrUpdateInternalHostResource
// (kdexhost_controller.go:651-736). The resulting InternalHost has the same
// name + namespace as the source; spec is inlined verbatim; UtilityPages refs
// and TranslationRefs synthesize the Internal* ref fields.
func ProjectHost(host kdexv1alpha1.KDexHost, in ProjectInput) (ProjectedHost, error) {
	out := kdexv1alpha1.KDexInternalHost{
		ObjectMeta: metav1.ObjectMeta{
			Name:        host.Name,
			Namespace:   host.Namespace,
			Labels:      copyLabels(host.Labels, host.Name),
			Annotations: copyAnnotations(host.Annotations),
		},
		Spec: kdexv1alpha1.KDexInternalHostSpec{
			KDexHostSpec: *host.Spec.DeepCopy(),
		},
	}

	pr := ProjectedHost{KDexInternalHost: out}

	// Synthesize utility-page refs.
	if host.Spec.UtilityPages != nil {
		if ref := host.Spec.UtilityPages.LoginRef; ref != nil {
			if !lookupUtilityPage(in.UtilityPages, ref.Name, host.Namespace) {
				pr.Warnings = append(pr.Warnings, fmt.Sprintf("host %s/%s: LoginRef %q not found in loaded CR set; skipping", host.Namespace, host.Name, ref.Name))
			} else {
				pr.Spec.LoginRef = &corev1.LocalObjectReference{Name: utilityPageProjectedName(host.Name, "login")}
			}
		}
		if ref := host.Spec.UtilityPages.ErrorRef; ref != nil {
			if !lookupUtilityPage(in.UtilityPages, ref.Name, host.Namespace) {
				pr.Warnings = append(pr.Warnings, fmt.Sprintf("host %s/%s: ErrorRef %q not found; skipping", host.Namespace, host.Name, ref.Name))
			} else {
				pr.Spec.ErrorRef = &corev1.LocalObjectReference{Name: utilityPageProjectedName(host.Name, "error")}
			}
		}
		if ref := host.Spec.UtilityPages.AnnouncementRef; ref != nil {
			if !lookupUtilityPage(in.UtilityPages, ref.Name, host.Namespace) {
				pr.Warnings = append(pr.Warnings, fmt.Sprintf("host %s/%s: AnnouncementRef %q not found; skipping", host.Namespace, host.Name, ref.Name))
			} else {
				pr.Spec.AnnouncementRef = &corev1.LocalObjectReference{Name: utilityPageProjectedName(host.Name, "announcement")}
			}
		}
	}

	// Synthesize translation refs.
	for _, ref := range host.Spec.TranslationRefs {
		if !lookupTranslation(in.Translations, ref.Name, host.Namespace) {
			pr.Warnings = append(pr.Warnings, fmt.Sprintf("host %s/%s: TranslationRef %q not found; skipping", host.Namespace, host.Name, ref.Name))
			continue
		}
		pr.Spec.InternalTranslationRefs = append(pr.Spec.InternalTranslationRefs,
			corev1.LocalObjectReference{Name: translationProjectedName(host.Name, ref.Name)})
	}

	return pr, nil
}

// ProjectTranslation replicates nexus-manager's createOrUpdateInternalTranslation
// (kdexhost_controller_util.go:36-112). Name is "<host>-<source>", namespace is
// the host's namespace (even if the source was a cluster-scoped translation in
// nexus-manager — preview consolidates everything into the host's namespace).
func ProjectTranslation(tr kdexv1alpha1.KDexTranslation, host kdexv1alpha1.KDexHost) kdexv1alpha1.KDexInternalTranslation {
	return kdexv1alpha1.KDexInternalTranslation{
		ObjectMeta: metav1.ObjectMeta{
			Name:        translationProjectedName(host.Name, tr.Name),
			Namespace:   host.Namespace,
			Labels:      copyLabels(tr.Labels, host.Name),
			Annotations: copyAnnotations(tr.Annotations),
		},
		Spec: kdexv1alpha1.KDexInternalTranslationSpec{
			KDexTranslationSpec: *tr.Spec.KDexTranslationSpec.DeepCopy(),
			HostRef:             corev1.LocalObjectReference{Name: host.Name},
		},
	}
}

// ProjectUtilityPage replicates nexus-manager's createOrUpdateInternalUtilityPage
// (kdexhost_controller_util.go:114-181). The output Name is "<host>-<lowercase-type>"
// — the source utility page's own name is discarded.
func ProjectUtilityPage(up kdexv1alpha1.KDexUtilityPage, host kdexv1alpha1.KDexHost) kdexv1alpha1.KDexInternalUtilityPage {
	return kdexv1alpha1.KDexInternalUtilityPage{
		ObjectMeta: metav1.ObjectMeta{
			Name:        utilityPageProjectedName(host.Name, string(up.Spec.Type)),
			Namespace:   host.Namespace,
			Labels:      copyLabels(up.Labels, host.Name),
			Annotations: copyAnnotations(up.Annotations),
		},
		Spec: kdexv1alpha1.KDexInternalUtilityPageSpec{
			KDexUtilityPageSpec: *up.Spec.DeepCopy(),
			HostRef:             corev1.LocalObjectReference{Name: host.Name},
		},
	}
}

// translationProjectedName returns the InternalTranslation name nexus-manager
// generates: "<host>-<source>". Matches kdexhost_controller_util.go:43.
func translationProjectedName(hostName, translationName string) string {
	return hostName + "-" + translationName
}

// utilityPageProjectedName returns the InternalUtilityPage name:
// "<host>-<lowercase-type>". Matches kdexhost_controller_util.go:121.
func utilityPageProjectedName(hostName, pageType string) string {
	return hostName + "-" + strings.ToLower(pageType)
}

func lookupUtilityPage(pages []kdexv1alpha1.KDexUtilityPage, name, namespace string) bool {
	for i := range pages {
		if pages[i].Name == name && pages[i].Namespace == namespace {
			return true
		}
	}
	return false
}

func lookupTranslation(translations []kdexv1alpha1.KDexTranslation, name, namespace string) bool {
	for i := range translations {
		if translations[i].Name == name && translations[i].Namespace == namespace {
			return true
		}
	}
	return false
}

// copyLabels copies the source labels then stamps the nexus-manager standard
// labels (app.kubernetes.io/name, kdex.dev/instance) last so they cannot be
// clobbered by a source label of the same name. The `kdex.dev/generation`
// label is not synthesized — preview has no real generation tracking.
func copyLabels(src map[string]string, hostName string) map[string]string {
	out := make(map[string]string, len(src)+2)
	for k, v := range src {
		out[k] = v
	}
	out["app.kubernetes.io/name"] = "kdex-host"
	out["kdex.dev/instance"] = hostName
	return out
}

func copyAnnotations(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
