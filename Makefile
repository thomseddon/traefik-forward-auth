
format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

test:
	go test -v ./...

.PHONY: mock
mock: ## run testify mockery for all the interfaces
	rm -rf mocks
	mockery --all --dir pkg --output ./mocks/pkg --keeptree

.PHONY: format test

workenv-image-cibuild:
	@test -n "$(CIRCLE_BRANCH)"
	docker build -t astrocr.azurecr.io/astronomer/traefik-forward-auth-workenv:$(CIRCLE_BRANCH)-$(GIT_SHA_SHORT)-$(BUILD_TIME) -t astrocr.azurecr.io/astronomer/traefik-forward-auth-workenv:$(CIRCLE_BRANCH) -f ./images/traefik-forward-auth-workenv/Dockerfile ./images/traefik-forward-auth-workenv
	docker push astrocr.azurecr.io/astronomer/traefik-forward-auth-workenv:$(CIRCLE_BRANCH)
	docker push astrocr.azurecr.io/astronomer/traefik-forward-auth-workenv:$(CIRCLE_BRANCH)-$(GIT_SHA_SHORT)-$(BUILD_TIME)