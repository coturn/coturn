FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

ARG FILC_VERSION=0.678
ARG FILC_URL=https://github.com/pizlonator/fil-c/releases/download/v${FILC_VERSION}/optfil-${FILC_VERSION}-linux-x86_64.tar.xz

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      cmake \
      curl \
      file \
      gawk \
      git \
      iproute2 \
      make \
      net-tools \
      pkg-config \
      procps \
      python3 \
      tar \
      unzip \
      xz-utils \
 && rm -rf /var/lib/apt/lists/*

# The optfil release tarball wraps a nested fil.tar.xz that extracts to
# /opt/fil. We avoid the bundled setup.sh (interactive, attempts SSH/user
# setup) and just unpack the inner archive directly. set -eux makes any
# failure self-describing in the docker-build log.
RUN set -eux; \
    curl -fL --retry 5 --retry-delay 2 --retry-all-errors --max-time 600 \
         -o /tmp/optfil-outer.tar.xz "${FILC_URL}"; \
    ls -la /tmp/optfil-outer.tar.xz; \
    mkdir -p /tmp/optfil-extract /opt; \
    tar -C /tmp/optfil-extract -xf /tmp/optfil-outer.tar.xz; \
    inner=$(ls /tmp/optfil-extract/*/fil.tar.xz | head -n 1); \
    test -n "${inner}"; \
    tar -C /opt -xf "${inner}"; \
    rm -rf /tmp/optfil-outer.tar.xz /tmp/optfil-extract; \
    test -x /opt/fil/bin/filcc; \
    /opt/fil/bin/filcc --version

ENV PATH=/opt/fil/bin:${PATH}
ENV CC=filcc
ENV CXX=fil++
# Make CMake's find_package look at /opt/fil first so coturn links the
# Fil-C-built OpenSSL/libevent/sqlite, not the Ubuntu ones.
ENV CMAKE_PREFIX_PATH=/opt/fil
ENV PKG_CONFIG_PATH=/opt/fil/lib/pkgconfig:/opt/fil/lib64/pkgconfig

WORKDIR /src

COPY docker-entrypoint.sh /usr/local/bin/coturn-filc-local
COPY build.sh             /usr/local/bin/coturn-filc-build
RUN chmod +x /usr/local/bin/coturn-filc-local /usr/local/bin/coturn-filc-build

ENTRYPOINT ["/usr/local/bin/coturn-filc-local"]
