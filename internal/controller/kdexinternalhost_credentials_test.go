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
	"encoding/base64"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	remoteauth "oras.land/oras-go/v2/registry/remote/auth"
)

func mkDockerConfigSecret(name string, created time.Time, body string) corev1.Secret {
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(created),
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: []byte(body),
		},
	}
}

var _ = Describe("getRegistryCredential", func() {
	r := &KDexInternalHostReconciler{}

	It("returns empty when no dockerconfigjson secrets exist", func() {
		secrets := kdexv1alpha1.Secrets{}
		Expect(r.getRegistryCredential("registry.example.com", secrets)).To(Equal(remoteauth.EmptyCredential))
	})

	It("returns the credential when username/password are present", func() {
		secrets := kdexv1alpha1.Secrets{
			mkDockerConfigSecret("a", time.Unix(1, 0), `{"auths":{"registry.example.com":{"username":"u","password":"p"}}}`),
		}
		Expect(r.getRegistryCredential("registry.example.com", secrets)).To(Equal(
			remoteauth.Credential{Username: "u", Password: "p"},
		))
	})

	It("decodes the standard 'auth' field when username/password are empty (issue #3)", func() {
		auth := base64.StdEncoding.EncodeToString([]byte("u:p"))
		secrets := kdexv1alpha1.Secrets{
			mkDockerConfigSecret("a", time.Unix(1, 0), `{"auths":{"registry.example.com":{"auth":"`+auth+`"}}}`),
		}
		Expect(r.getRegistryCredential("registry.example.com", secrets)).To(Equal(
			remoteauth.Credential{Username: "u", Password: "p"},
		))
	})

	It("decodes 'auth' with a colon inside the password", func() {
		// password contains a colon: secret password is "p:q"
		auth := base64.StdEncoding.EncodeToString([]byte("user:p:q"))
		secrets := kdexv1alpha1.Secrets{
			mkDockerConfigSecret("a", time.Unix(1, 0), `{"auths":{"registry.example.com":{"auth":"`+auth+`"}}}`),
		}
		Expect(r.getRegistryCredential("registry.example.com", secrets)).To(Equal(
			remoteauth.Credential{Username: "user", Password: "p:q"},
		))
	})

	It("ignores a malformed 'auth' field and tries the next secret", func() {
		good := base64.StdEncoding.EncodeToString([]byte("u:p"))
		secrets := kdexv1alpha1.Secrets{
			mkDockerConfigSecret("newest", time.Unix(2, 0), `{"auths":{"registry.example.com":{"auth":"!!not-base64!!"}}}`),
			mkDockerConfigSecret("older", time.Unix(1, 0), `{"auths":{"registry.example.com":{"auth":"`+good+`"}}}`),
		}
		Expect(r.getRegistryCredential("registry.example.com", secrets)).To(Equal(
			remoteauth.Credential{Username: "u", Password: "p"},
		))
	})

	It("consults all dockerconfigjson secrets to find a matching registry (issue #2)", func() {
		secrets := kdexv1alpha1.Secrets{
			mkDockerConfigSecret("newest", time.Unix(2, 0), `{"auths":{"other.example.com":{"username":"x","password":"y"}}}`),
			mkDockerConfigSecret("older", time.Unix(1, 0), `{"auths":{"registry.example.com":{"username":"u","password":"p"}}}`),
		}
		Expect(r.getRegistryCredential("registry.example.com", secrets)).To(Equal(
			remoteauth.Credential{Username: "u", Password: "p"},
		))
	})

	It("returns empty when the registry is not present in any secret", func() {
		secrets := kdexv1alpha1.Secrets{
			mkDockerConfigSecret("a", time.Unix(1, 0), `{"auths":{"other.example.com":{"username":"u","password":"p"}}}`),
		}
		Expect(r.getRegistryCredential("registry.example.com", secrets)).To(Equal(remoteauth.EmptyCredential))
	})

	It("skips secrets with malformed JSON and continues searching", func() {
		secrets := kdexv1alpha1.Secrets{
			mkDockerConfigSecret("newest", time.Unix(2, 0), `not-json`),
			mkDockerConfigSecret("older", time.Unix(1, 0), `{"auths":{"registry.example.com":{"username":"u","password":"p"}}}`),
		}
		Expect(r.getRegistryCredential("registry.example.com", secrets)).To(Equal(
			remoteauth.Credential{Username: "u", Password: "p"},
		))
	})

	It("ignores non-dockerconfigjson secrets", func() {
		opaque := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "opaque", CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"registry.example.com":{"username":"u","password":"p"}}}`)},
		}
		secrets := kdexv1alpha1.Secrets{opaque}
		Expect(r.getRegistryCredential("registry.example.com", secrets)).To(Equal(remoteauth.EmptyCredential))
	})
})
