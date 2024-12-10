#
# Dockerfile of coturn/coturn:debian Docker image.
#

ARG debian_ver=bookworm




#
# Stage 'dist-libprom' creates prometheus-client-c distribution.
#

# We compile prometheus-client-c from sources, because Debian doesn't provide
# it as its package yet.
#
# TODO: Re-check this to be present in packages on next Debian major version update.

# https://hub.docker.com/_/debian
FROM debian:${debian_ver}-slim AS dist-libprom

# Install tools for building.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-install-suggests \
            ca-certificates cmake g++ git make \
 && update-ca-certificates

# Install prometheus-client-c build dependencies.
RUN apt-get install -y --no-install-recommends --no-install-suggests \
            libmicrohttpd-dev

# Prepare prometheus-client-c sources for building.
ARG prom_ver=0.1.3
RUN mkdir -p /build/ && cd /build/ \
 && git init \
 && git remote add origin https://github.com/digitalocean/prometheus-client-c \
 && git fetch --depth=1 origin "v${prom_ver}" \
 && git checkout FETCH_HEAD

# Build libprom.so from sources.
RUN mkdir -p /build/prom/build/ && cd /build/prom/build/ \
 && TEST=0 cmake -G "Unix Makefiles" \
                 -DCMAKE_INSTALL_PREFIX=/usr \
                 -DCMAKE_SKIP_BUILD_RPATH=TRUE \
                 -DCMAKE_C_FLAGS="-DPROM_LOG_ENABLE -g -O3" \
                 .. \
 && make

# Install prometheus-client-c.
RUN LIBS_DIR=/out/$(dirname $(find /usr/ -name libc.so)) \
 && mkdir -p $LIBS_DIR/ \
 && cp -rf /build/prom/build/libprom.so \
       $LIBS_DIR/ \
 && mkdir -p /out/usr/include/ \
 && cp -rf /build/prom/include/* \
       /out/usr/include/ \
 # Preserve license file.
 && mkdir -p /out/usr/share/licenses/prometheus-client-c/ \
 && cp /build/LICENSE /out/usr/share/licenses/prometheus-client-c/




#
# Stage 'dist-coturn' creates Coturn distribution.
#

# https://hub.docker.com/_/debian
FROM debian:${debian_ver}-slim AS dist-coturn

# Install tools for building.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-install-suggests \
            autoconf ca-certificates coreutils g++ git libtool make pkg-config \
 && update-ca-certificates

# Install Coturn build dependencies.
RUN apt-get install -y --no-install-recommends --no-install-suggests \
            libevent-dev \
            libssl-dev \
            libpq-dev libmariadb-dev libsqlite3-dev \
            libhiredis-dev \
            libmongoc-dev \
            libmicrohttpd-dev

# Install prometheus-client-c distribution.
COPY --from=dist-libprom /out/ /

# Prepare local Coturn sources for building.
COPY CMakeLists.txt \
     configure \
     INSTALL \
     LICENSE \
     make-man.sh Makefile.in \
     postinstall.txt \
     README.turn* \
     /app/
COPY cmake/ /app/cmake/
COPY examples/ /app/examples/
COPY man/ /app/man/
COPY src/ /app/src/
COPY turndb/ /app/turndb/
WORKDIR /app/

# Use Coturn sources from Git if `coturn_git_ref` is specified.
ARG coturn_git_ref=HEAD
ARG coturn_github_url=https://github.com
ARG coturn_github_repo=coturn/coturn

RUN if [ "${coturn_git_ref}" != 'HEAD' ]; then true \
 && rm -rf /app/* \
 && git init \
 && git remote add origin ${coturn_github_url}/${coturn_github_repo} \
 && git fetch --depth=1 origin "${coturn_git_ref}" \
 && git checkout FETCH_HEAD \
 && true; fi

# Build Coturn from sources.
RUN ./configure --prefix=/usr \
                --turndbdir=/var/lib/coturn \
                --disable-rpath \
                --sysconfdir=/etc/coturn \
                # No documentation included to keep image size smaller.
                --mandir=/tmp/coturn/man \
                --docsdir=/tmp/coturn/docs \
                --examplesdir=/tmp/coturn/examples \
 && make

# Install and configure Coturn.
RUN mkdir -p /out/ \
 && DESTDIR=/out make install \
 # Remove redundant files.
 && rm -rf /out/tmp/ \
 # Preserve license file.
 && mkdir -p /out/usr/share/licenses/coturn/ \
 && cp LICENSE /out/usr/share/licenses/coturn/ \
 # Remove default config file.
 && rm -f /out/etc/coturn/turnserver.conf.default

# Install helper tools of Docker image.
COPY docker/coturn/rootfs/ /out/
RUN chmod +x /out/usr/local/bin/docker-entrypoint.sh \
             /out/usr/local/bin/detect-external-ip.sh
RUN ln -s /usr/local/bin/detect-external-ip.sh \
          /out/usr/local/bin/detect-external-ip
RUN chown -R nobody:nogroup /out/var/lib/coturn/

# Re-export prometheus-client-c distribution.
COPY --from=dist-libprom /out/ /out/




#
# Stage 'runtime' creates final Docker image to use in runtime.
#

# https://hub.docker.com/_/debian
FROM debian:${debian_ver}-slim AS runtime

# Update system packages.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends --no-install-suggests \
            ca-certificates \
 && update-ca-certificates \
 # Install Coturn dependencies.
 && apt-get install -y --no-install-recommends --no-install-suggests \
            libatomic1 \
            libevent-2.1-7 libevent-core-2.1-7 libevent-extra-2.1-7 \
            libevent-openssl-2.1-7 libevent-pthreads-2.1-7 \
            libssl3 \
            libpq5 libmariadb3 libsqlite3-0 \
            libhiredis0.14 \
            libmongoc-1.0-0 \
            libmicrohttpd12 \
 # Install `dig` tool for `detect-external-ip.sh`.
 && apt-get install -y --no-install-recommends --no-install-suggests \
            dnsutils \
 # Cleanup unnecessary stuff.
 && rm -rf /var/lib/apt/lists/*

# Install Coturn distribution.
COPY --from=dist-coturn /out/ /

# Allow non-root using privileged ports.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-install-suggests \
            libcap2-bin \
 && setcap CAP_NET_BIND_SERVICE=+ep /usr/bin/turnserver \
 # Cleanup unnecessary stuff.
 && apt-get purge -y --auto-remove \
                  -o APT::AutoRemove::RecommendsImportant=false \
            libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

USER nobody:nogroup

EXPOSE 3478 3478/udp 5349 5349/udp

VOLUME ["/var/lib/coturn"]

ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["--log-file=stdout", "--external-ip=$(detect-external-ip)"]
