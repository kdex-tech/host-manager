package page

import (
	"github.com/kdex-tech/entitlements"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PageHandler struct {
	Content            map[string]PackedContent
	Footer             string
	Header             string
	MainTemplate       string
	Name               string
	Navigations        map[string]string
	PackageReferences  []kdexv1alpha1.PackageReference
	Page               *kdexv1alpha1.KDexPageSpec
	ParsedRequirements *entitlements.ParsedRequirements
	RequiredBackends   []kdexv1alpha1.KDexObjectReference
	Scripts            []kdexv1alpha1.ScriptDef
	Status             *kdexv1alpha1.KDexObjectStatus
	UtilityPage        *kdexv1alpha1.KDexUtilityPageSpec

	checksum string
}

type PackedContent struct {
	AppName           string
	AppGeneration     string
	Attributes        map[string]string
	Content           string
	CustomElementName string
	Slot              string
}

type ResolvedContentEntry struct {
	App     *kdexv1alpha1.KDexAppSpec
	AppObj  client.Object
	Content PackedContent
}

type ResolvedNavigation struct {
	Generation int64
	Name       string
	Spec       *kdexv1alpha1.KDexPageNavigationSpec
}
