
format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

test:
	go test -v ./...

docker:
	docker buildx build --platform=linux/amd64,linux/arm64,linux/386,linux/arm/v7,linux/arm/v6 -t ${DOCKER_TAG} --push .

.PHONY: format test docker
