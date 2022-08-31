PROJECT = libsodium
PROJECT_DESCRIPTION = libsodium Port Driver
PROJECT_VERSION = 2.0.0

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-shell docker-test

DOCKER_OTP_VERSION ?= 25.0.4-alpine-3.16.1

docker-build::
	$(gen_verbose) docker build \
		--tag ${PROJECT}-${DOCKER_OTP_VERSION} \
		--file test/Dockerfile \
		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
		test

docker-load::
	$(gen_verbose) docker load \
		-i "${PROJECT}-${DOCKER_OTP_VERSION}/image.tar"

docker-save::
	$(verbose) mkdir -p "${PROJECT}-${DOCKER_OTP_VERSION}"
	$(gen_verbose) docker save \
		-o "${PROJECT}-${DOCKER_OTP_VERSION}/image.tar" \
		${PROJECT}-${DOCKER_OTP_VERSION}

docker-setup::
	$(verbose) if [ -f "${PROJECT}-${DOCKER_OTP_VERSION}/image.tar" ]; then \
		$(MAKE) docker-load; \
	else \
		$(MAKE) docker-build; \
		$(MAKE) docker-save; \
	fi

docker-shell::
	$(verbose) docker run \
		-v "$(shell pwd)":"/build/${PROJECT}" --rm -it "${PROJECT}-${DOCKER_OTP_VERSION}" \
		/bin/bash -l

docker-test::
	$(gen_verbose) docker run \
		-v "$(shell pwd)":"/build/${PROJECT}" "${PROJECT}-${DOCKER_OTP_VERSION}" \
		/bin/bash -c 'cd ${PROJECT} && make ct'
