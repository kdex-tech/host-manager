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
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// The IPR renders its .npmrc from Secrets it does not own, so a rotation of
// one of them must enqueue the IPR or the next packager Job runs on a revoked
// credential. See kdex-tech/host-manager#239.
var _ = Describe("KDexInternalPackageReferencesReconciler.secretToRequests", func() {
	const (
		ns        = "kdex"
		focalHost = "rsi"
	)

	var (
		ctx    context.Context
		scheme *runtime.Scheme
	)

	host := func(selector *metav1.LabelSelector) *kdexv1alpha1.KDexInternalHost {
		h := &kdexv1alpha1.KDexInternalHost{
			ObjectMeta: metav1.ObjectMeta{Name: focalHost, Namespace: ns},
		}
		h.Spec.SecretSelector = selector
		return h
	}

	ipr := func(name, hostName string, refs ...kdexv1alpha1.PackageReference) *kdexv1alpha1.KDexInternalPackageReferences {
		return &kdexv1alpha1.KDexInternalPackageReferences{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: kdexv1alpha1.KDexInternalPackageReferencesSpec{
				HostRef:           corev1.LocalObjectReference{Name: hostName},
				PackageReferences: refs,
			},
		}
	}

	pkg := func(name string, secretRef *kdexv1alpha1.KDexObjectReference) kdexv1alpha1.PackageReference {
		return kdexv1alpha1.PackageReference{Name: name, Version: "1.0.0", SecretRef: secretRef}
	}

	secret := func(namespace, name string, labels, annotations map[string]string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace, Labels: labels, Annotations: annotations,
		}}
	}

	reconciler := func(objs ...client.Object) *KDexInternalPackageReferencesReconciler {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
		return &KDexInternalPackageReferencesReconciler{
			Client: c, Scheme: scheme, ControllerNamespace: ns, FocalHost: focalHost,
		}
	}

	req := func(name string) reconcile.Request {
		return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}
	}

	hostSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"kdex.dev/host": focalHost}}
	hostLabels := map[string]string{"kdex.dev/host": focalHost}
	npm := map[string]string{"kdex.dev/secret-type": "npm"}

	BeforeEach(func() {
		ctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(kdexv1alpha1.AddToScheme(scheme)).To(Succeed())
	})

	It("enqueues the IPR whose packageReference names the Secret", func() {
		r := reconciler(
			host(nil),
			ipr("rsi-packages", focalHost, pkg("@acme/a", &kdexv1alpha1.KDexObjectReference{Name: "gitlab-npm", Kind: "Secret"})),
		)

		Expect(r.secretToRequests(ctx, secret(ns, "gitlab-npm", nil, nil))).To(ConsistOf(req("rsi-packages")))
	})

	It("honours a secretRef namespace and ignores a same-named Secret in the IPR namespace", func() {
		r := reconciler(
			host(nil),
			ipr("rsi-packages", focalHost, pkg("@acme/a", &kdexv1alpha1.KDexObjectReference{Name: "gitlab-npm", Kind: "Secret", Namespace: "creds"})),
		)

		Expect(r.secretToRequests(ctx, secret("creds", "gitlab-npm", nil, nil))).To(ConsistOf(req("rsi-packages")))
		Expect(r.secretToRequests(ctx, secret(ns, "gitlab-npm", nil, nil))).To(BeEmpty())
	})

	It("enqueues every focal-host IPR for a selected npm Secret", func() {
		r := reconciler(
			host(hostSelector),
			ipr("rsi-packages", focalHost, pkg("@acme/a", nil)),
			ipr("rsi-more", focalHost, pkg("@acme/b", nil)),
		)

		Expect(r.secretToRequests(ctx, secret(ns, "npm-auth", hostLabels, npm))).To(ConsistOf(req("rsi-packages"), req("rsi-more")))
	})

	It("ignores a selected Secret that is not an npm Secret", func() {
		r := reconciler(host(hostSelector), ipr("rsi-packages", focalHost, pkg("@acme/a", nil)))

		Expect(r.secretToRequests(ctx, secret(ns, "jwt-keys", hostLabels, nil))).To(BeEmpty())
	})

	It("ignores an npm Secret the host selector does not match", func() {
		r := reconciler(host(hostSelector), ipr("rsi-packages", focalHost, pkg("@acme/a", nil)))

		Expect(r.secretToRequests(ctx, secret(ns, "npm-auth", map[string]string{"kdex.dev/host": "other"}, npm))).To(BeEmpty())
	})

	It("ignores an npm Secret when the host has no selector", func() {
		r := reconciler(host(nil), ipr("rsi-packages", focalHost, pkg("@acme/a", nil)))

		Expect(r.secretToRequests(ctx, secret(ns, "npm-auth", hostLabels, npm))).To(BeEmpty())
	})

	It("never enqueues another host's IPR", func() {
		r := reconciler(
			host(hostSelector),
			ipr("other-packages", "other", pkg("@acme/a", &kdexv1alpha1.KDexObjectReference{Name: "gitlab-npm", Kind: "Secret"})),
		)

		Expect(r.secretToRequests(ctx, secret(ns, "gitlab-npm", hostLabels, npm))).To(BeEmpty())
	})

	It("enqueues an IPR once when the Secret is both selected and referenced", func() {
		r := reconciler(
			host(hostSelector),
			ipr("rsi-packages", focalHost, pkg("@acme/a", &kdexv1alpha1.KDexObjectReference{Name: "npm-auth", Kind: "Secret"})),
		)

		Expect(r.secretToRequests(ctx, secret(ns, "npm-auth", hostLabels, npm))).To(ConsistOf(req("rsi-packages")))
	})
})

// A Secret watch on a cluster-wide cache sees every write; only a change the
// render reads may re-render (and re-verify) the IPR.
var _ = Describe("npmSecretChanged", func() {
	base := func() *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "npm-auth", Namespace: "kdex",
				Labels:      map[string]string{"kdex.dev/host": "rsi"},
				Annotations: map[string]string{"kdex.dev/secret-type": "npm"},
			},
			Data: map[string][]byte{".npmrc": []byte("//r/:_authToken=old")},
		}
	}

	It("fires when the data changes", func() {
		changed := base()
		changed.Data[".npmrc"] = []byte("//r/:_authToken=new")
		Expect(npmSecretChanged(base(), changed)).To(BeTrue())
	})

	It("fires when the labels change, since they decide selection", func() {
		changed := base()
		changed.Labels = nil
		Expect(npmSecretChanged(base(), changed)).To(BeTrue())
	})

	It("fires when the secret-type annotation changes", func() {
		changed := base()
		delete(changed.Annotations, "kdex.dev/secret-type")
		Expect(npmSecretChanged(base(), changed)).To(BeTrue())
	})

	It("ignores a metadata-only write such as a force-sync annotation", func() {
		changed := base()
		changed.Annotations["force-sync"] = "1729200000"
		changed.ResourceVersion = "42"
		Expect(npmSecretChanged(base(), changed)).To(BeFalse())
	})
})
