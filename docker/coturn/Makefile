###############################
# Common defaults/definitions #
###############################

comma := ,
empty :=
space := $(empty) $(empty)

# Checks two given strings for equality.
eq = $(if $(or $(1),$(2)),$(and $(findstring $(1),$(2)),\
                                $(findstring $(2),$(1))),1)




######################
# Project parameters #
######################

COTURN_VER ?= 4.5.2
COTURN_MIN_VER = $(strip $(shell echo $(COTURN_VER) | cut -d '.' -f1,2))
COTURN_MAJ_VER = $(strip $(shell echo $(COTURN_VER) | cut -d '.' -f1))

BUILD_REV ?= 2

NAMESPACES := coturn \
              ghcr.io/coturn \
              quay.io/coturn
NAME := coturn
ALL_IMAGES := \
	debian:$(COTURN_VER)-r$(BUILD_REV)-debian,$(COTURN_VER)-debian,$(COTURN_MIN_VER)-debian,$(COTURN_MAJ_VER)-debian,debian,$(COTURN_VER)-r$(BUILD_REV),$(COTURN_VER),$(COTURN_MIN_VER),$(COTURN_MAJ_VER),latest \
	alpine:$(COTURN_VER)-r$(BUILD_REV)-alpine,$(COTURN_VER)-alpine,$(COTURN_MIN_VER)-alpine,$(COTURN_MAJ_VER)-alpine,alpine
#	<Dockerfile>:<version>,<tag1>,<tag2>,...

# Default is first image from ALL_IMAGES list.
DOCKERFILE ?= $(word 1,$(subst :, ,$(word 1,$(ALL_IMAGES))))
TAGS ?= $(word 1,$(subst |, ,\
	$(word 2,!$(subst $(DOCKERFILE):, ,$(subst $(space),|,$(ALL_IMAGES))))))
VERSION ?= $(word 1,$(subst -, ,$(TAGS)))-$(word 2,$(strip \
	$(subst -, ,$(subst $(comma), ,$(TAGS)))))

PLATFORMS ?= linux/amd64 \
             linux/arm64 \
             linux/arm/v6 \
             linux/arm/v7 \
             linux/ppc64le \
             linux/s390x
MAIN_PLATFORM ?= $(word 1,$(subst $(comma), ,$(PLATFORMS)))




###########
# Aliases #
###########

image: docker.image

push: docker.push

release: git.release

test: test.docker




###################
# Docker commands #
###################

docker-namespaces = $(strip $(if $(call eq,$(namespaces),),\
                            $(NAMESPACES),$(subst $(comma), ,$(namespaces))))
docker-tags = $(subst $(comma), ,$(strip \
                      $(if $(call eq,$(tags),),$(TAGS),$(tags))))
docker-platforms = $(strip $(if $(call eq,$(platforms),),\
                           $(PLATFORMS),$(subst $(comma), ,$(platforms))))

# Runs `docker buildx build` command allowing to customize it for the purpose of
# re-tagging or pushing.
define docker.buildx
	$(eval dockerfile := $(strip $(1)))
	$(eval namespace := $(strip $(2)))
	$(eval tag := $(strip $(3)))
	$(eval git-ref := $(strip $(4)))
	$(eval platform := $(strip $(5)))
	$(eval no-cache := $(strip $(6)))
	$(eval args := $(strip $(7)))
	cd ../../ && \
	docker buildx build --force-rm $(args) \
		--platform $(platform) \
		$(if $(call eq,$(no-cache),yes),--no-cache --pull,) \
		$(if $(call eq,$(git-ref),),,--build-arg coturn_git_ref=$(git-ref)) \
		-f docker/coturn/$(dockerfile)/Dockerfile \
		-t $(namespace)/$(NAME):$(tag) ./
endef


# Pre-build cache for Docker image builds.
#
# WARNING: This command doesn't apply tag to the built Docker image, just
#          creates a build cache. To produce a Docker image with a tag, use
#          `docker.tag` command right after running this one.
#
# Usage:
#	make docker.build.cache [DOCKERFILE=(debian|alpine)]
#		[platforms=($(PLATFORMS)|<platform-1>[,<platform-2>...])]
#		[no-cache=(no|yes)]
#		[ref=<git-ref>]

docker.build.cache:
	$(call docker.buildx,$(DOCKERFILE),\
		coturn,\
		build-cache,\
		$(ref),\
		$(shell echo "$(docker-platforms)" | tr -s '[:blank:]' ','),\
		$(no-cache),\
		--output 'type=image$(comma)push=false')


# Build Docker image on the given platform with the given tag.
#
# Usage:
#	make docker.image [DOCKERFILE=(debian|alpine)]
#		[tag=($(VERSION)|<tag>)]
#		[platform=($(MAIN_PLATFORM)|<platform>)]
#		[no-cache=(no|yes)]
#		[ref=<git-ref>]

docker.image:
	$(call docker.buildx,$(DOCKERFILE),\
		coturn,\
		$(if $(call eq,$(tag),),$(VERSION),$(tag)),\
		$(ref),\
		$(if $(call eq,$(platform),),$(MAIN_PLATFORM),$(platform)),\
		$(no-cache),\
		--load)


# Push Docker images to their repositories (container registries),
# along with the required multi-arch manifests.
#
# Usage:
#	make docker.push [DOCKERFILE=(debian|alpine)]
#		[namespaces=($(NAMESPACES)|<prefix-1>[,<prefix-2>...])]
#		[tags=($(TAGS)|<tag-1>[,<tag-2>...])]
#		[platforms=($(PLATFORMS)|<platform-1>[,<platform-2>...])]
#		[ref=<git-ref>]

docker.push:
	$(foreach namespace,$(docker-namespaces),\
		$(foreach tag,$(docker-tags),\
			$(call docker.buildx,$(DOCKERFILE),\
				$(namespace),\
				$(tag),\
				$(ref),\
				$(shell echo "$(docker-platforms)" | tr -s '[:blank:]' ','),,\
				--push)))




####################
# Testing commands #
####################

# Run Bats tests for Docker image.
#
# Documentation of Bats:
#	https://github.com/bats-core/bats-core
#
# Usage:
#	make test.docker
#		[tag=($(VERSION)|<tag>)]
#		[platforms=($(MAIN_PLATFORM)|@all|<platform-1>[,<platform-2>...])]
#		[( [build=no]
#		 | build=yes [DOCKERFILE=(debian|alpine)]
#		             [ref=<git-ref>] )]
#		[with=ipv6]

test-docker-platforms = $(strip $(if $(call eq,$(platforms),),$(MAIN_PLATFORM),\
                                $(if $(call eq,$(platforms),@all),$(PLATFORMS),\
                                $(docker-platforms))))
test.docker:
ifeq ($(wildcard node_modules/.bin/bats),)
	@make npm.install
endif
	$(foreach platform,$(test-docker-platforms),\
		$(call test.docker.do,\
			$(if $(call eq,$(tag),),$(VERSION),$(tag)),\
			$(platform)))
define test.docker.do
	$(eval tag := $(strip $(1)))
	$(eval platform := $(strip $(2)))
	$(if $(call eq,$(build),yes),\
		@make docker.image DOCKERFILE=$(DOCKERFILE) \
			no-cache=no tag=$(tag) platform=$(platform) ref=$(ref) ,)
	IMAGE=coturn/$(NAME):$(tag) PLATFORM=$(platform) \
	$(if $(call eq,$(with),ipv6),TEST_IPV6=1,) \
	node_modules/.bin/bats \
		--timing $(if $(call eq,$(CI),),--pretty,--formatter tap) \
		tests/main.bats
endef




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

git-release-tag = docker/$(strip $(if $(call eq,$(ver),),$(VERSION),$(ver)))

git.release:
ifeq ($(shell git rev-parse $(git-release-tag) >/dev/null 2>&1 && echo "ok"),ok)
	$(error "Git tag $(git-release-tag) already exists")
endif
	git tag $(git-release-tag)
	git push origin refs/tags/$(git-release-tag)




##################
# .PHONY section #
##################

.PHONY: image push release test \
        docker.build.cache docker.image docker.push \
        git.release \
        npm.install \
        test.docker
