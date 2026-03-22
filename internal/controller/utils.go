package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/jsonpath"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func CRDExists(mgr ctrl.Manager, gvk schema.GroupVersionKind) (bool, error) {
	_, err := mgr.GetRESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		if meta.IsNoMatchError(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func CollectBackend(defaultServerImage string, requiredBackends *[]kdexv1alpha1.KDexObjectReference, obj client.Object) {
	if obj == nil {
		return
	}

	var backend kdexv1alpha1.Backend
	switch v := obj.(type) {
	case *kdexv1alpha1.KDexClusterApp:
		backend = v.Spec.Backend
	case *kdexv1alpha1.KDexClusterScriptLibrary:
		backend = v.Spec.Backend
	case *kdexv1alpha1.KDexClusterTheme:
		backend = v.Spec.Backend
	case *kdexv1alpha1.KDexApp:
		backend = v.Spec.Backend
	case *kdexv1alpha1.KDexInternalHost:
		backend = v.Spec.Backend
	case *kdexv1alpha1.KDexScriptLibrary:
		backend = v.Spec.Backend
	case *kdexv1alpha1.KDexTheme:
		backend = v.Spec.Backend
	default:
		return
	}

	if backend.IsConfigured(defaultServerImage) {
		ref := kdexv1alpha1.KDexObjectReference{
			Kind:      obj.GetObjectKind().GroupVersionKind().Kind,
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		}
		found := false
		for _, rb := range *requiredBackends {
			if rb.Name == ref.Name && rb.Kind == ref.Kind && rb.Namespace == ref.Namespace {
				found = true
				break
			}
		}
		if !found {
			*requiredBackends = append(*requiredBackends, ref)
		}
	}
}

func HashScriptDef(script kdexv1alpha1.ScriptDef) string {
	hash := sha256.Sum256([]byte(script.ToTag()))
	return hex.EncodeToString(hash[:])
}

// nolint:gocyclo
func MakeHandlerByReferencePath(
	c client.Client,
	scheme *runtime.Scheme,
	watcherType client.Object,
	list client.ObjectList,
	referencePath ...string,
) handler.EventHandler {
	watcherKind, err := getKind(watcherType, scheme)
	if err != nil {
		panic(err)
	}

	const level = 3

	log := logf.Log.WithName(
		strings.ToLower(watcherKind),
	).WithName(
		"watch",
	).WithValues(
		"referencePaths", referencePath,
	)

	jpRefs := make([]*jsonpath.JSONPath, len(referencePath))
	for i, refPath := range referencePath {
		jpRefs[i] = jsonpath.New("ref-path-" + strconv.Itoa(i))
		if err := jpRefs[i].Parse(refPath); err != nil {
			panic(err)
		}
	}

	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		objKind, err := getKind(o, scheme)
		if err != nil {
			log.Error(err, "failed to get object kind", "object", o)
			return []reconcile.Request{}
		}

		if err := c.List(ctx, list, client.InNamespace(ControllerNamespace())); err != nil {
			return []reconcile.Request{}
		}

		items, err := meta.ExtractList(list)
		if err != nil || len(items) == 0 {
			return []reconcile.Request{}
		}

		requests := []reconcile.Request{}
		for _, i := range items {
			item := i.(client.Object)

			log.V(level).Info("processing item", "object", item.GetName(), "namespace", item.GetNamespace())

			for j, jpRef := range jpRefs {
				curPath := referencePath[j]
				jsonPathReference, err := jpRef.FindResults(item)
				if err != nil {
					log.V(level).Info("skipping", "path", curPath, "err", err, "object", item.GetName(), "namespace", item.GetNamespace())
					continue
				}
				if len(jsonPathReference) == 0 || len(jsonPathReference[0]) == 0 {
					log.V(level).Info("skipping", "path", curPath, "object", item.GetName(), "namespace", item.GetNamespace())
					continue
				}

				log.V(level).Info("field found", "path", curPath, "object", item.GetName(), "namespace", item.GetNamespace())

				for idx, node := range jsonPathReference {
					for _, curRef := range node {
						ref := reflect.ValueOf(curRef.Interface())

						log.V(level).Info("reference", "reference", ref, "object", item.GetName(), "node", idx)

						isNil := false
						switch ref.Kind() {
						case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
							isNil = ref.IsNil()
						}
						if ref.IsZero() || isNil {
							continue
						}

						theReferenceStruct := ref.Interface()

						log.V(level).Info("struct", "interface", theReferenceStruct, "object", item.GetName(), "node", idx)

						switch v := theReferenceStruct.(type) {
						case string:
							if v == o.GetName() {
								requests = append(requests, reconcile.Request{
									NamespacedName: types.NamespacedName{
										Name:      item.GetName(),
										Namespace: item.GetNamespace(),
									},
								})
							}
						case []string:
							if slices.Contains(v, o.GetName()) {
								requests = append(requests, reconcile.Request{
									NamespacedName: types.NamespacedName{
										Name:      item.GetName(),
										Namespace: item.GetNamespace(),
									},
								})
							}
						case corev1.LocalObjectReference:
							if v.Name == o.GetName() && item.GetNamespace() == o.GetNamespace() {
								requests = append(requests, reconcile.Request{
									NamespacedName: types.NamespacedName{
										Name:      item.GetName(),
										Namespace: item.GetNamespace(),
									},
								})
							}
						case *corev1.LocalObjectReference:
							if v.Name == o.GetName() && item.GetNamespace() == o.GetNamespace() {
								requests = append(requests, reconcile.Request{
									NamespacedName: types.NamespacedName{
										Name:      item.GetName(),
										Namespace: item.GetNamespace(),
									},
								})
							}
						case kdexv1alpha1.KDexObjectReference:
							namespace := item.GetNamespace()
							if v.Namespace != "" {
								namespace = v.Namespace
							}

							isMatch := v.Kind == objKind && v.Name == o.GetName()
							if isMatch && !strings.Contains(objKind, "Cluster") {
								isMatch = o.GetNamespace() == namespace
							}

							if isMatch {
								requests = append(requests, reconcile.Request{
									NamespacedName: types.NamespacedName{
										Name:      item.GetName(),
										Namespace: item.GetNamespace(),
									},
								})
							}
						case *kdexv1alpha1.KDexObjectReference:
							namespace := item.GetNamespace()
							if v.Namespace != "" {
								namespace = v.Namespace
							}

							isMatch := v.Kind == objKind && v.Name == o.GetName()
							if isMatch && !strings.Contains(objKind, "Cluster") {
								isMatch = o.GetNamespace() == namespace
							}

							if isMatch {
								requests = append(requests, reconcile.Request{
									NamespacedName: types.NamespacedName{
										Name:      item.GetName(),
										Namespace: item.GetNamespace(),
									},
								})
							}
						}
					}
				}
			}
		}
		return requests
	})
}

func LogConstructor(name string, mgr ctrl.Manager) func(request *reconcile.Request) logr.Logger {
	return func(request *reconcile.Request) logr.Logger {
		l := mgr.GetControllerOptions().Logger.WithName(name)
		if request != nil {
			l = l.WithValues("namespace", request.Namespace, "name", request.Name)
		}
		return l
	}
}

func ControllerNamespace() string {
	in, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return os.Getenv("POD_NAMESPACE")
	}

	return string(in)
}

func UniqueBackendRefs(backends []kdexv1alpha1.KDexObjectReference) []kdexv1alpha1.KDexObjectReference {
	seen := map[string]bool{}
	unique := []kdexv1alpha1.KDexObjectReference{}
	for _, backend := range backends {
		if seen[backend.Name] {
			continue
		}
		seen[backend.Name] = true
		unique = append(unique, backend)
	}

	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Name < unique[j].Name
	})

	return unique
}

func UniquePackageRefs(packages []kdexv1alpha1.PackageReference) []kdexv1alpha1.PackageReference {
	packageReferenceMap := map[string]kdexv1alpha1.PackageReference{}
	for _, pkgRef := range packages {
		packageReferenceMap[pkgRef.Name+"@"+pkgRef.Version] = pkgRef
	}

	uniquePackageReferences := make([]kdexv1alpha1.PackageReference, 0, len(packageReferenceMap))
	for _, pkgRef := range packageReferenceMap {
		uniquePackageReferences = append(uniquePackageReferences, pkgRef)
	}

	sort.Slice(uniquePackageReferences, func(i, j int) bool {
		if uniquePackageReferences[i].Name != uniquePackageReferences[j].Name {
			return uniquePackageReferences[i].Name < uniquePackageReferences[j].Name
		}
		return uniquePackageReferences[i].Version < uniquePackageReferences[j].Version
	})

	return uniquePackageReferences
}

func UniqueScriptDefs(scripts []kdexv1alpha1.ScriptDef) []kdexv1alpha1.ScriptDef {
	uniqueScripts := []kdexv1alpha1.ScriptDef{}

	seenScripts := map[string]bool{}
	for _, script := range scripts {
		hash := HashScriptDef(script)
		if seenScripts[hash] {
			continue
		}
		seenScripts[hash] = true
		uniqueScripts = append(uniqueScripts, script)
	}

	return uniqueScripts
}

func getKind(obj client.Object, scheme *runtime.Scheme) (string, error) {
	gvk, err := apiutil.GVKForObject(obj, scheme)
	if err != nil {
		return "", err
	}
	return gvk.Kind, nil
}
