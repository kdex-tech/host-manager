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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	corev1 "k8s.io/api/core/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	remoteauth "oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// openImageLayers resolves an image reference and returns its layer
// descriptors along with a fetcher for their blobs.
//
// Extracted from PullImportMap so the packages-image verification added for
// kdex-tech/host-manager#161 can read the same image from a different
// controller without duplicating registry/auth setup. The two consumers differ
// only in which layer they want: the importmap (smallest tar+gzip) or
// node_modules (largest).
func openImageLayers(
	ctx context.Context,
	imageRef string,
	secrets kdexv1alpha1.Secrets,
) ([]ImportmapLayer, LayerFetcher, error) {
	repo, err := remote.NewRepository(imageRef)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create repository client: %w", err)
	}

	registryURL, err := url.Parse("//" + repo.Reference.Registry)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse registry URL: %w", err)
	}

	// Local registries are served over plain HTTP.
	if strings.HasSuffix(registryURL.Hostname(), ".local") {
		repo.PlainHTTP = true
	}

	cred := registryCredential(repo.Reference.Registry, secrets)
	if cred.Username != "" {
		repo.Client = &remoteauth.Client{
			Client: retry.DefaultClient,
			Cache:  remoteauth.NewCache(),
			Credential: func(ctx context.Context, s string) (remoteauth.Credential, error) {
				return cred, nil
			},
		}
	}

	// Resolve to a manifest (handles OCI index/multi-arch).
	descriptor, err := oras.Resolve(ctx, repo, repo.Reference.Reference, oras.ResolveOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve image: %w", err)
	}

	rc, err := repo.Fetch(ctx, descriptor)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	manifestData, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	layers := make([]ImportmapLayer, 0, len(manifest.Layers))
	for _, l := range manifest.Layers {
		layers = append(layers, ImportmapLayer{
			MediaType: l.MediaType,
			Digest:    digest.Digest(l.Digest),
			Size:      l.Size,
		})
	}

	fetch := func(ctx context.Context, l ImportmapLayer) (io.ReadCloser, error) {
		return repo.Fetch(ctx, ocispec.Descriptor{
			MediaType: l.MediaType,
			Digest:    l.Digest,
			Size:      l.Size,
		})
	}

	return layers, fetch, nil
}

// registryCredential resolves a docker-config secret into a registry
// credential for the given registry host. Returns EmptyCredential when no
// secret covers it.
func registryCredential(registry string, secrets kdexv1alpha1.Secrets) remoteauth.Credential {
	dockerSecrets := secrets.Filter(func(s corev1.Secret) bool { return s.Type == corev1.SecretTypeDockerConfigJson })

	for _, s := range dockerSecrets {
		var config struct {
			Auths map[string]struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Auth     string `json:"auth"`
			} `json:"auths"`
		}

		if err := json.Unmarshal(s.Data[corev1.DockerConfigJsonKey], &config); err != nil {
			continue
		}

		a, ok := config.Auths[registry]
		if !ok {
			continue
		}

		if a.Username == "" && a.Password == "" && a.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(a.Auth)
			if err != nil {
				continue
			}
			i := strings.IndexByte(string(decoded), ':')
			if i < 0 {
				continue
			}
			a.Username = string(decoded[:i])
			a.Password = string(decoded[i+1:])
		}

		return remoteauth.Credential{Username: a.Username, Password: a.Password}
	}

	return remoteauth.EmptyCredential
}
