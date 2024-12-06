###############################
# Common defaults/definitions #
###############################

comma := ,
empty :=
space := $(empty) $(empty)

# Checks two given strings for equality.
eq = $(if $(or $(1),$(2)),$(and $(findstring $(1),$(2)),\
                                $(findstring $(2),$(1))),1)

# Maps platform identifier to the one accepted by Docker CLI.
dockerify = $(strip $(if $(call eq,$(1),linux/arm32v6),linux/arm/v6,\
                    $(if $(call eq,$(1),linux/arm32v7),linux/arm/v7,\
                    $(if $(call eq,$(1),linux/arm64v8),linux/arm64/v8,\
                    $(if $(call eq,$(1),linux/i386),   linux/386,\
                                                       $(platform))))))




######################
# Project parameters #
######################

COTURN_VER ?= 4.6.2
COTURN_MIN_VER = $(strip $(shell echo $(COTURN_VER) | cut -d '.' -f1,2))
COTURN_MAJ_VER = $(strip $(shell echo $(COTURN_VER) | cut -d '.' -f1))

ALPINE_VER := alpine$(strip $(shell grep -m1 'alpine_ver=' alpine/Dockerfile \
                                    | cut -d '=' -f2 \
                                    | cut -d '.' -f1,2))
DEBIAN_VER := $(strip $(shell grep -m1 'debian_ver=' debian/Dockerfile \
                              | cut -d '=' -f2))

BUILD_REV ?= 13

NAME := coturn
OWNER := $(or $(GITHUB_REPOSITORY_OWNER),coturn)
REGISTRIES := $(strip $(subst $(comma), ,\
	$(shell grep -m1 'registry: \["' ../../.github/workflows/docker.yml \
	        | cut -d':' -f2 | tr -d '"][')))
ALL_IMAGES := \
	debian:$(COTURN_VER)-r$(BUILD_REV)-debian,$(COTURN_VER)-debian,$(COTURN_MIN_VER)-debian,$(COTURN_MAJ_VER)-debian,debian,$(COTURN_VER)-$(DEBIAN_VER),$(COTURN_MIN_VER)-$(DEBIAN_VER),$(COTURN_MAJ_VER)-$(DEBIAN_VER),$(DEBIAN_VER),$(COTURN_VER)-r$(BUILD_REV),$(COTURN_VER),$(COTURN_MIN_VER),$(COTURN_MAJ_VER),latest \
	alpine:$(COTURN_VER)-r$(BUILD_REV)-alpine,$(COTURN_VER)-alpine,$(COTURN_MIN_VER)-alpine,$(COTURN_MAJ_VER)-alpine,alpine,$(COTURN_VER)-$(ALPINE_VER),$(COTURN_MIN_VER)-$(ALPINE_VER),$(COTURN_MAJ_VER)-$(ALPINE_VER),$(ALPINE_VER)
#	<Dockerfile>:<version>,<tag1>,<tag2>,...

# Default is first image from ALL_IMAGES list.
DOCKERFILE ?= $(word 1,$(subst :, ,$(word 1,$(ALL_IMAGES))))
TAGS ?= $(word 1,$(subst |, ,\
	$(word 2,!$(subst $(DOCKERFILE):, ,$(subst $(space),|,$(ALL_IMAGES))))))
VERSION ?= $(word 1,$(subst -, ,$(TAGS)))-$(word 2,$(strip \
	$(subst -, ,$(subst $(comma), ,$(TAGS)))))




###########
# Aliases #
###########

image: docker.image

manifest: docker.manifest

push: docker.push

release: git.release

tags: docker.tags

test: test.docker




###################
# Docker commands #
###################

docker-registries = $(strip \
	$(or $(subst $(comma), ,$(registries)),$(REGISTRIES)))
docker-tags = $(strip $(or $(subst $(comma), ,$(tags)),$(TAGS)))


# Build single-platform Docker image with the given tag.
#
# Usage:
#	make docker.image [dockerfile=(debian|alpine)]
#	                  [tag=($(VERSION)|<docker-tag>)]] [no-cache=(no|yes)]
#	                  [platform=<os>/<arch>]
#	                  [ref=<git-ref>]

github_url := $(strip $(or $(GITHUB_SERVER_URL),https://github.com))
github_repo := $(strip $(or $(GITHUB_REPOSITORY),$(OWNER)/$(NAME)))

docker.image:
	cd ../../ && \
	docker buildx build --force-rm \
		$(if $(call eq,$(platform),),,--platform $(call dockerify,$(platform)))\
		$(if $(call eq,$(no-cache),yes),--no-cache --pull,) \
		$(if $(call eq,$(ref),),,--build-arg coturn_git_ref=$(ref)) \
		--build-arg coturn_github_url=$(github_url) \
		--build-arg coturn_github_repo=$(github_repo) \
		--label org.opencontainers.image.source=$(github_url)/$(github_repo) \
		--label org.opencontainers.image.revision=$(strip \
			$(shell git show --pretty=format:%H --no-patch)) \
		--label org.opencontainers.image.version=$(subst docker/,,$(strip \
			$(shell git describe --tags --dirty --match='docker/*'))) \
		-f docker/coturn/$(or $(dockerfile),$(DOCKERFILE))/Dockerfile \
		--load -t $(OWNER)/$(NAME):$(or $(tag),$(VERSION)) ./


# Unite multiple single-platform Docker images as a multi-platform Docker image.
#
# WARNING: All the single-platform Docker images should be present on their
#          remote registry. This is the limitation imposed by `docker manifest`
#          command.
#
#	make docker.manifest [amend=(yes|no)] [push=(no|yes)]
#	                     [of=($(VERSION)|<docker-tag-1>[,<docker-tag-2>...])]
#	                     [tags=($(TAGS)|<docker-tag-1>[,<docker-tag-2>...])]
#	                     [registries=($(REGISTRIES)|<prefix-1>[,<prefix-2>...])]

docker.manifest:
	$(foreach tag,$(subst $(comma), ,$(docker-tags)),\
		$(foreach registry,$(subst $(comma), ,$(docker-registries)),\
			$(call docker.manifest.create.do,$(or $(of),$(VERSION)),\
			                                 $(registry),$(tag))))
ifeq ($(push),yes)
	$(foreach tag,$(subst $(comma), ,$(docker-tags)),\
		$(foreach registry,$(subst $(comma), ,$(docker-registries)),\
			$(call docker.manifest.push.do,$(registry),$(tag))))
endif
define docker.manifest.create.do
	$(eval froms := $(strip $(1)))
	$(eval repo := $(strip $(2)))
	$(eval tag := $(strip $(3)))
	docker manifest create $(if $(call eq,$(amend),no),,--amend) \
		$(repo)/$(OWNER)/$(NAME):$(tag) \
		$(foreach from,$(subst $(comma), ,$(froms)),\
			$(repo)/$(OWNER)/$(NAME):$(from))
endef
define docker.manifest.push.do
	$(eval repo := $(strip $(1)))
	$(eval tag := $(strip $(2)))
	docker manifest push $(repo)/$(OWNER)/$(NAME):$(tag)
endef


# Manually push single-platform Docker images to container registries.
#
# Usage:
#	make docker.push [tags=($(TAGS)|<docker-tag-1>[,<docker-tag-2>...])]
#	                 [registries=($(REGISTRIES)|<prefix-1>[,<prefix-2>...])]

docker.push:
	$(foreach tag,$(subst $(comma), ,$(docker-tags)),\
		$(foreach registry,$(subst $(comma), ,$(docker-registries)),\
			$(call docker.push.do,$(registry),$(tag))))
define docker.push.do
	$(eval repo := $(strip $(1)))
	$(eval tag := $(strip $(2)))
	docker push $(repo)/$(OWNER)/$(NAME):$(tag)
endef


# Tag single-platform Docker image with the given tags.
#
# Usage:
#	make docker.tags [of=($(VERSION)|<docker-tag>)]
#	                 [tags=($(TAGS)|<docker-tag-1>[,<docker-tag-2>...])]
#	                 [registries=($(REGISTRIES)|<prefix-1>[,<prefix-2>...])]

docker.tags:
	$(foreach tag,$(subst $(comma), ,$(docker-tags)),\
		$(foreach registry,$(subst $(comma), ,$(docker-registries)),\
			$(call docker.tags.do,$(or $(of),$(VERSION)),$(registry),$(tag))))
define docker.tags.do
	$(eval from := $(strip $(1)))
	$(eval repo := $(strip $(2)))
	$(eval to := $(strip $(3)))
	docker tag $(OWNER)/$(NAME):$(from) $(repo)/$(OWNER)/$(NAME):$(to)
endef


# Save single-platform Docker images to a tarball file.
#
# Usage:
#	make docker.tar [to-file=(.cache/image.tar|<file-path>)]
#	                [tags=($(VERSION)|<docker-tag-1>[,<docker-tag-2>...])]

docker-tar-file = $(or $(to-file),.cache/image.tar)

docker.tar:
	@mkdir -p $(dir $(docker-tar-file))
	docker save -o $(docker-tar-file) \
		$(foreach tag,$(subst $(comma), ,$(or $(tags),$(VERSION))),\
			$(OWNER)/$(NAME):$(tag))


docker.test: test.docker


# Load single-platform Docker images from a tarball file.
#
# Usage:
#	make docker.untar [from-file=(.cache/image.tar|<file-path>)]

docker.untar:
	docker load -i $(or $(from-file),.cache/image.tar)




####################
# Testing commands #
####################

# Run Bats tests for Docker image.
#
# Documentation of Bats:
#	https://github.com/bats-core/bats-core
#
# Usage:
#	make test.docker [tag=($(VERSION)|<docker-tag>)]
#	                 [platform=(linux/amd64|<os>/<arch>)]
#	                 [with=ipv6]

test.docker:
ifeq ($(wildcard node_modules/.bin/bats),)
	@make npm.install
endif
	IMAGE=$(OWNER)/$(NAME):$(or $(tag),$(VERSION)) \
	PLATFORM=$(or $(call dockerify,$(platform)),linux/amd64) \
	$(if $(call eq,$(with),ipv6),TEST_IPV6=1,) \
	node_modules/.bin/bats \
		--timing $(if $(call eq,$(CI),),--pretty,--formatter tap) \
		--print-output-on-failure \
		tests/main.bats




################
# NPM commands #
################

# Resolve project NPM dependencies.
#
# Usage:
#	make npm.install [dockerized=(no|yes)]

npm.install:
ifeq ($(dockerized),yes)
	docker run --rm --network=host -v "$(PWD)":/app/ -w /app/ \
		node \
			make npm.install dockerized=no
else
	npm install
endif




################
# Git commands #
################

# Release project version (apply version tag and push).
#
# Usage:
#	make git.release [ver=($(VERSION)|<proj-ver>)]

git-release-tag = docker/$(strip $(or $(ver),$(VERSION)))

git.release:
ifeq ($(shell git rev-parse $(git-release-tag) >/dev/null 2>&1 && echo "ok"),ok)
	$(error "Git tag $(git-release-tag) already exists")
endif
	git tag $(git-release-tag)
	git push origin refs/tags/$(git-release-tag)




##################
# .PHONY section #
##################

.PHONY: image manifest push release test \
        docker.image docker.manifest docker.push docker.tags docker.tar \
        docker.test docker.untar \
        git.release \
        npm.install \
        test.docker
