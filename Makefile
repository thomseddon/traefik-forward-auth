GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

GO_OPT= -mod vendor -ldflags "-X main.Branch=$(GIT_BRANCH) -X main.Revision=$(GIT_REVISION) -X main.Version=$(VERSION)"

KO_OPTS ?= --push=false --tags dev

# More exclusions can be added similar with: -not -path './testbed/*'
ALL_SRC := $(shell find . -name '*.go' \
								-not -path './vendor*/*' \
                                -type f | sort)

# ALL_PKGS is used with 'go cover'
ALL_PKGS := $(shell go list $(sort $(dir $(ALL_SRC))))

.PHONY: build
build:
	GO111MODULE=on CGO_ENABLED=0 go build $(GO_OPT) -o ./bin/$(GOOS)/traefik-forward-auth-$(GOARCH) $(BUILD_INFO) ./cmd

.PHONY: docker
docker:
	KO_DOCKER_REPO=bendonnelly/traefik-forward-auth ko build --bare --platform=linux/amd64,linux/arm64 $(KO_OPTS) ./cmd

.PHONY: format
format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

## Tests
GOTEST_OPT?= -race -timeout 20m -count=1 -v
GOTEST_OPT_WITH_COVERAGE = $(GOTEST_OPT) -cover
GOTEST=go test
GO_JUNIT_REPORT=2>&1 | go-junit-report -parser gojson -iocopy -out report.xml

.PHONY: test
test:
	$(GOTEST) $(GOTEST_OPT) $(ALL_PKGS)

.PHONY: test-with-cover-report
test-with-cover-report:
	$(GOTEST) $(GOTEST_OPT_WITH_COVERAGE) -json $(ALL_PKGS) $(GO_JUNIT_REPORT)

FILES_TO_FMT=$(shell find . -type d \( -path ./vendor \) -prune -o -name '*.go' -print)

.PHONY: fmt check-fmt
fmt:
	@gofumpt -l -w .
	@goimports -w $(FILES_TO_FMT)

check-fmt: fmt
	@git diff --exit-code -- $(FILES_TO_FMT)