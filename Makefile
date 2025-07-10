
format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

test:
	go test -v ./...

.PHONY: mock
mock: ## run testify mockery for all the interfaces
	rm -rf mocks
	mockery --all --dir pkg --output ./mocks/pkg --keeptree

.PHONY: format test
