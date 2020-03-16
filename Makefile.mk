#
#   Copyright 2015  Xebia Nederland B.V.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
REGISTRY_HOST=docker.io
USERNAME=$(USER)
NAME=$(shell basename $(CURDIR))

RELEASE_SUPPORT := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/.make-release-support
IMAGE=$(REGISTRY_HOST)/$(USERNAME)/$(NAME)

VERSION=$(shell . $(RELEASE_SUPPORT) ; getVersion)
TAG=$(shell . $(RELEASE_SUPPORT); getTag)

SHELL=/bin/bash

DOCKER_BUILD_CONTEXT=.
DOCKER_FILE_PATH=Dockerfile

.PHONY: pre-build docker-build post-build build release patch-release minor-release major-release tag check-status check-release showver \
	push pre-push do-push post-push

build: pre-build docker-build post-build

pre-build:


post-build:


pre-push:


post-push:



docker-build: .release
	docker build $(DOCKER_BUILD_ARGS) -t $(IMAGE):$(VERSION) $(DOCKER_BUILD_CONTEXT) -f $(DOCKER_FILE_PATH)
	@DOCKER_MAJOR=$(shell docker -v | sed -e 's/.*version //' -e 's/,.*//' | cut -d\. -f1) ; \
	DOCKER_MINOR=$(shell docker -v | sed -e 's/.*version //' -e 's/,.*//' | cut -d\. -f2) ; \
	if [ $$DOCKER_MAJOR -eq 1 ] && [ $$DOCKER_MINOR -lt 10 ] ; then \
		echo docker tag -f $(IMAGE):$(VERSION) $(IMAGE):latest ;\
		docker tag -f $(IMAGE):$(VERSION) $(IMAGE):latest ;\
	else \
		echo docker tag $(IMAGE):$(VERSION) $(IMAGE):latest ;\
		docker tag $(IMAGE):$(VERSION) $(IMAGE):latest ; \
	fi

.release:
	@echo "release=0.0.0" > .release
	@echo "tag=$(NAME)-0.0.0" >> .release
	@echo INFO: .release created
	@cat .release


release: check-status check-release build push


push: pre-push do-push post-push 

do-push: 
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

snapshot: build push

showver: .release
	@. $(RELEASE_SUPPORT); getVersion

tag-patch-release: VERSION := $(shell . $(RELEASE_SUPPORT); nextPatchLevel)
tag-patch-release: .release tag 

tag-minor-release: VERSION := $(shell . $(RELEASE_SUPPORT); nextMinorLevel)
tag-minor-release: .release tag 

tag-major-release: VERSION := $(shell . $(RELEASE_SUPPORT); nextMajorLevel)
tag-major-release: .release tag 

patch-release: tag-patch-release release
	@echo $(VERSION)

minor-release: tag-minor-release release
	@echo $(VERSION)

major-release: tag-major-release release
	@echo $(VERSION)


tag: TAG=$(shell . $(RELEASE_SUPPORT); getTag $(VERSION))
tag: check-status
	@. $(RELEASE_SUPPORT) ; ! tagExists $(TAG) || (echo "ERROR: tag $(TAG) for version $(VERSION) already tagged in git" >&2 && exit 1) ;
	@. $(RELEASE_SUPPORT) ; setRelease $(VERSION)
	git add .
	git commit -m "bumped to version $(VERSION)" ;
	git tag $(TAG) ;
	@ if [ -n "$(shell git remote -v)" ] ; then git push --tags ; else echo 'no remote to push tags to' ; fi

check-status:
	@. $(RELEASE_SUPPORT) ; ! hasChanges || (echo "ERROR: there are still outstanding changes" >&2 && exit 1) ;

check-release: .release
	@. $(RELEASE_SUPPORT) ; tagExists $(TAG) || (echo "ERROR: version not yet tagged in git. make [minor,major,patch]-release." >&2 && exit 1) ;
	@. $(RELEASE_SUPPORT) ; ! differsFromRelease $(TAG) || (echo "ERROR: current directory differs from tagged $(TAG). make [minor,major,patch]-release." ; exit 1)
