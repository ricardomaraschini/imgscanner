IMGSCANNER = imgscanner
VERSION ?= v0.0.0

REGISTRY_HOSTNAME ?= ghcr.io
REGISTRY_USERNAME ?= shipwright-io

IMAGE_BUILDER ?= podman
IMAGE_TAG ?= latest
IMAGE ?= $(REGISTRY_HOSTNAME)/$(REGISTRY_USERNAME)/$(IMGSCANNER)

OUTPUT_DIR ?= output
OUTPUT_BIN = $(OUTPUT_DIR)/bin
OUTPUT_DOC = $(OUTPUT_DIR)/doc

IMGSCANNER_BIN = $(OUTPUT_BIN)/$(IMGSCANNER)
GEN_BIN = $(OUTPUT_DIR)/code-generator

PROJECT = github.com/ricardomaraschini/imgscanner
GEN_OUTPUT = /tmp/$(PROJECT)/apis/scans/v1beta1

# destination namespace to install target
NAMESPACE ?= shipwright-build

# the container image produced by ko will use this repostory, and combine with the application name
# being compiled
KO_DOCKER_REPO ?= $(REGISTRY_HOSTNAME)/$(REGISTRY_USERNAME)

# golang flags are exported through the enviroment variables, reaching all targets
GOFLAGS ?= -mod=vendor -ldflags='-Xmain.Version=$(VERSION)'
CGO_ENABLED ?= 0

.EXPORT_ALL_VARIABLES:

default: build

build: $(IMGSCANNER)

.PHONY: $(IMGSCANNER)
$(IMGSCANNER):
	go build \
		-tags containers_image_openpgp \
		-o $(IMGSCANNER_BIN) \
		./cmd/$(IMGSCANNER)

.PHONY: get-code-generator
get-code-generator:
	rm -rf $(GEN_BIN) || true
	git clone --depth=1 \
		--branch v0.23.5 \
		https://github.com/kubernetes/code-generator.git \
		$(GEN_BIN)
	cd $(GEN_BIN); go mod vendor

.PHONY: generate-k8s
generate-k8s:
	rm -rf $(GEN_OUTPUT) || true
	$(GEN_BIN)/generate-groups.sh all \
		$(PROJECT)/apis/scans/v1beta1/generated \
		$(PROJECT) \
		apis/scans:v1beta1 \
		--go-header-file=$(GEN_BIN)/hack/boilerplate.go.txt \
		--output-base=/tmp
	rm -rf apis/scans/v1beta1/generated
	mv $(GEN_OUTPUT)/* apis/scans/v1beta1/

.PHONY: image
image:
	$(IMAGE_BUILDER) build -f Containerfile -t $(IMAGE) .

.PHONY: clean
clean:
	rm -rf $(OUTPUT_DIR)
