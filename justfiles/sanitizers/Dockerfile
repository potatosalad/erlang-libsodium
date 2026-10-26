# syntax=docker/dockerfile:1

FROM buildpack-deps:trixie AS otp-build

ARG OTP_VERSION="29.1.1"
ARG BUILD_JOBS=4

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        libclang-rt-dev \
        libssl-dev \
        llvm \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    OTP_DOWNLOAD_URL="https://github.com/erlang/otp/releases/download/OTP-${OTP_VERSION}/otp_src_${OTP_VERSION}.tar.gz"; \
    OTP_DOWNLOAD_SHA256="054e0143e39c780e091107fc9b345792a9c1a55f6bac1eca1c1101510fc06bf6"; \
    curl -fSL -o otp-src.tar.gz "$OTP_DOWNLOAD_URL"; \
    echo "$OTP_DOWNLOAD_SHA256  otp-src.tar.gz" | sha256sum -c -; \
    mkdir -p /usr/src/otp; \
    tar -xzf otp-src.tar.gz -C /usr/src/otp --strip-components=1; \
    rm otp-src.tar.gz; \
    cd /usr/src/otp; \
    ./otp_build autoconf; \
    gnuArch="$(dpkg-architecture --query DEB_HOST_GNU_TYPE)"; \
    sslLibSubdir="lib/$(dpkg-architecture --query DEB_HOST_MULTIARCH)"; \
    CC=clang CXX=clang++ ./configure \
        --build="$gnuArch" \
        --prefix=/opt/erlang \
        --disable-sctp \
        --without-javac \
        --without-odbc \
        --without-wx \
        --with-ssl=/usr \
        --with-ssl-lib-subdir="$sslLibSubdir"

RUN set -eux; \
    export ERL_TOP=/usr/src/otp; \
    cd "$ERL_TOP"; \
    make -j"${BUILD_JOBS}"; \
    make -j"${BUILD_JOBS}" TYPE=asan; \
    make install; \
    make release TYPE=asan RELEASE_ROOT=/opt/erlang/lib/erlang; \
    install -m 0644 erts/emulator/asan/suppress /opt/erlang/lib/erlang/asan.supp; \
    ASAN_OPTIONS=detect_leaks=0 /opt/erlang/bin/erl -emu_type asan -noshell \
        -eval 'asan = erlang:system_info(emu_type), halt().'

FROM buildpack-deps:trixie

ENV OTP_VERSION="29.1.1"

LABEL org.opencontainers.image.version=$OTP_VERSION

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        just \
        libclang-rt-dev \
        libssl3t64 \
        llvm \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=otp-build /opt/erlang /opt/erlang
ENV PATH="/opt/erlang/bin:${PATH}"

RUN ASAN_OPTIONS=detect_leaks=0 erl -emu_type asan -noshell \
        -eval 'asan = erlang:system_info(emu_type), halt().'

WORKDIR /project
COPY . .

ENV SANITIZERS_LSAN_SUPPRESSIONS=/opt/erlang/lib/erlang/asan.supp \
    SANITIZERS_RESTORE_BUILD=0

CMD ["bash", "justfiles/sanitizers/run.sh", "/project"]
