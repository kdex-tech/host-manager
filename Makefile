REPOSITORY ?=
IMG ?= kdex-tech/host-manager
TAG ?= $(shell git describe --dirty='-d' --tags)

# if REPOSITORY is set make sure it ends with a /
ifneq ($(REPOSITORY),)
override REPOSITORY := $(REPOSITORY)/
endif

# if TAG is set make sure it starts with a :
ifneq ($(TAG),)
override TAG := :$(TAG)
endif

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

TEST_PKGS ?= $(shell go list ./... | grep -v /e2e)
TEST_ARGS ?=
.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
ifeq ($(DEBUG),true)
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" dlv test $(TEST_PKGS) --headless --listen=:2345 --api-version=2 -- $(TEST_ARGS)
else
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $(TEST_PKGS) -coverprofile cover.out $(TEST_ARGS)
endif

.PHONY: coverage
coverage: test ## Generate and view test coverage report.
	@echo "--> Generating coverage report"
	go tool cover -html=cover.out -o cover.html
	@echo "--> Coverage report generated at file://$$(pwd)/cover.html"

.PHONY: lint
lint: golangci-lint lint-chart ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint modernizer-fix ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify

.PHONY: modernizer
modernizer: ## Run modernizer
	go run golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest -test ./...

.PHONY: modernizer-fix
modernizer-fix: ## Run modernizer and perform fixes
	go run golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest -fix ./...

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${REPOSITORY}${IMG}${TAG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${REPOSITORY}${IMG}${TAG}

# If your build fails to push to the k3d registry you may have to do this:
#
# # 1. Create a buildkit configuration to allow the insecure registry
# cat <<EOF > buildkitd.toml
# [registry."k3d-registry:5000"]
#   http = true
#   insecure = true
# EOF
#
# # 2. Recreate the builder with the network AND the config
# docker buildx rm kdex-builder || true
# docker buildx create --name kdex-builder \
#   --driver docker-container \
#   --driver-opt network=k3d-playground \
#   --config buildkitd.toml \
#   --use
#
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	$(CONTAINER_TOOL) buildx inspect kdex-builder >/dev/null 2>&1 || $(CONTAINER_TOOL) buildx create --name kdex-builder --use
	$(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${REPOSITORY}${IMG}${TAG} --tag ${REPOSITORY}${IMG}:latest -f Dockerfile.cross .
	rm Dockerfile.cross


.PHONY: lint-chart
lint-chart: ## Lint chart.
	$(HELM) lint ./chart

.PHONY: deploy-chart
deploy-chart: ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	$(HELM) upgrade host-controller ./chart \
		--create-namespace \
		--install \
		--namespace kdex-nexus-system \
		--set "config.backendDefault.serverImage=${REPOSITORY}kdex-tech/backend-static:latest" \
		--set "config.backendDefault.serverImagePullPolicy=Always" \
		--set "config.hostDefault.deployment.template.spec.containers[0].image=${REPOSITORY}kdex-tech/host-manager:latest" \
		--set "config.hostDefault.deployment.template.spec.containers[0].imagePullPolicy=Always" \
		--set "config.packages.packagerImage=${REPOSITORY}kdex-tech/cli-tools:latest" \
		--set "config.packages.packagerImagePullPolicy=Always" \
		--set "config.packages.toolsImage=${REPOSITORY}kdex-tech/node-tools:latest" \
		--set "config.packages.toolsImagePullPolicy=Always" \
		--set "controllerManager.container.image.repository=${REPOSITORY}${IMG}" \
		--set "controllerManager.container.image.tag=latest" \
		--set "controllerManager.container.imagePullPolicy=Always" \
		--set "controllerManager.container.args[3]=--zap-log-level=info" \
		--set "controllerManager.container.args[4]=--named-log-level=helm=3" \
		--set "controllerManager.container.args[5]=--named-log-level=kdexhost=3" \
		--set "controllerManager.container.args[6]=--named-log-level=kdexhost.translation=info" \
		--set "controllerManager.container.args[7]=--named-log-level=kdexhost.utilitypage=info" \
		--set "controllerManager.container.args[8]=--named-log-level=kdexhost.watch=info" \
		--set "controllerManager.container.args[9]=--named-log-level=npm-registry=2"


.PHONY: undeploy-chart
undeploy-chart: ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	$(HELM) uninstall host-controller \
		--namespace kdex-nexus-system

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
HELM ?= helm

## Tool Versions
# https://github.com/kubernetes-sigs/controller-tools/releases/latest
CONTROLLER_TOOLS_VERSION ?= v0.20.1
# https://github.com/golangci/golangci-lint/releases/latest
GOLANGCI_LINT_VERSION ?= v2.10.1

#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $$(realpath $(1)-$(3)) $(1)
endef
