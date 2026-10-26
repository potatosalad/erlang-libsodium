docker_image := "erlang-libsodium-codegen"

_docker-exec +args: docker-build
    docker run --rm --volume "{{justfile_directory()}}:/project" {{docker_image}} {{args}}

_docker-interactive +args: docker-build
    docker run --rm --volume "{{justfile_directory()}}:/project" -it {{docker_image}} {{args}}

[group('docker')]
docker-build:
    docker build -f ./codegen/Dockerfile -t {{docker_image}} .

[group('docker')]
docker-codegen:
    @just _docker-exec just _codegen-in-docker

# The container shares the work tree: remove its Linux build outputs afterwards.
_codegen-in-docker: codegen
    gmake clean

[group('docker')]
docker-format:
    @just _docker-exec just format

[group('docker')]
docker-lock:
    @just _docker-exec just poetry-lock

[group('docker')]
docker-shell:
    @just _docker-interactive /bin/bash

[group('docker')]
docker-sign:
    @just _docker-exec just sign
