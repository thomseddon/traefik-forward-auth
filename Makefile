TAG_NAME := $(shell test -d .git && git describe --abbrev=0 --tags || echo "")
SHA := $(shell test -d .git && git rev-parse --short HEAD)
COMMIT := $(SHA)
# hide commit for releases
ifeq ($(RELEASE),1)
    COMMIT :=
endif
ARTEFACT := traefik-forward-auth
VERSION := $(if $(TAG_NAME),$(TAG_NAME),$(SHA))
BUILD_DATE := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_TAGS:= -a -installsuffix nocgo
#BUILD_ARGS := -trimpath

IMAGE := mabunixda/$(ARTEFACT)
PLATFORM := linux/arm64,linux/amd64,linux/arm/v7

default: clean format build

clean:
	rm -f $(ARTEFACT)

format:
	gofmt -w -l $$(find . -name '*.go')

test:
	go test -v ./...

porcelain::
	gofmt -w -l $$(find . -name '*.go')
	go mod tidy
	test -z "$$(git status --porcelain)" || (git status; git diff; false)

build::
	@echo Version: $(VERSION) $(SHA) $(BUILD_DATE)
	CGO_ENABLED=0 go build -o $(ARTEFACT) $(BUILD_TAGS) $(BUILD_ARGS) ./cmd/

docker::
	@echo Version: $(VERSION) $(SHA) $(BUILD_DATE)
	docker buildx build --platform $(PLATFORM) --tag $(IMAGE):testing .

publish-testing::
	@echo Version: $(VERSION) $(SHA) $(BUILD_DATE)
	docker build --platform $(PLATFORM) --tag $(IMAGE):testing --push .

publish-latest::
	@echo Version: $(VERSION) $(SHA) $(BUILD_DATE)
	docker build --platform $(PLATFORM) --tag $(IMAGE):latest --tag $(IMAGE):$(VERSION) --push .
