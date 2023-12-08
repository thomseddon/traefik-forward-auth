GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

GO_OPT= -mod vendor -ldflags "-X main.Branch=$(GIT_BRANCH) -X main.Revision=$(GIT_REVISION) -X main.Version=$(VERSION)"

KO_OPTS ?= --push=false --tags dev

.PHONY: build
build:
	GO111MODULE=on CGO_ENABLED=0 go build $(GO_OPT) -o ./bin/$(GOOS)/traefik-forward-auth-$(GOARCH) $(BUILD_INFO) ./cmd

.PHONY: docker
docker:
	KO_DOCKER_REPO=bendonnelly/traefik-forward-auth ${GOPATH}/bin/ko build --bare --platform=linux/amd64,linux/arm64 $(KO_OPTS) ./cmd

.PHONY: format test
format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

test:
	go test -v ./...


FILES_TO_FMT=$(shell find . -type d \( -path ./vendor \) -prune -o -name '*.go' -print)

.PHONY: fmt check-fmt
fmt:
	@gofumpt -l -w .
	@goimports -w $(FILES_TO_FMT)

check-fmt: fmt
	@git diff --exit-code -- $(FILES_TO_FMT)