
format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

test:
	go test -v ./...

.PHONY: format test
