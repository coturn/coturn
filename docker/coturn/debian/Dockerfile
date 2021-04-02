#
# Dockerfile of coturn/coturn:debian Docker image.
#

ARG debian_ver=buster




#
# Stage 'dist-mongoc' creates mongo-c-driver distribution.
#

# We compile mongo-c-driver from sources, because buster Debian `libmongoc` packages
# cointain too old driver version, being not compatible with latest MongoDB versions well.
#
# TODO: Reconsider this on next stable Debian version update.

# https://hub.docker.com/_/debian
FROM debian:${debian_ver}-slim AS dist-mongoc

# Install tools for building.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-install-suggests \
            ca-certificates cmake g++ gcc git make python \
 && update-ca-certificates

# Install mongo-c-driver build dependencies.
RUN apt-get install -y --no-install-recommends --no-install-suggests \
            libssl-dev

# Prepare mongo-c-driver sources for building.
ARG mongoc_ver=1.17.4
RUN mkdir -p /tmp/mongoc/src/ && cd /tmp/mongoc/src/ \
 && git init \
 && git remote add origin https://github.com/mongodb/mongo-c-driver \
 && git fetch --depth=1 origin "${mongoc_ver}" \
 && git checkout FETCH_HEAD \
 && python build/calc_release_version.py > VERSION_CURRENT

# Build mongo-c-driver from sources.
RUN mkdir -p /tmp/mongoc/build/ && cd /tmp/mongoc/build/ \
 && cmake -DENABLE_AUTOMATIC_INIT_AND_CLEANUP=OFF \
          -DCMAKE_BUILD_TYPE=Release \
          /tmp/mongoc/src

# Install mongo-c-driver.
RUN mkdir -p /out/ && cd /tmp/mongoc/build/ \
 && DESTDIR=/out cmake --build . --target install
# Preserve license file.
RUN mkdir -p /out/usr/share/licenses/mongo-c-driver/ \
 && cp /out/usr/local/share/mongo-c-driver/COPYING /out/usr/share/licenses/mongo-c-driver/ \
 # Remove redundant files.
 && rm -rf /out/usr/local/bin/ \
           /out/usr/local/share/




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
            libhiredis-dev

# Install mongo-c-driver distribution.
COPY --from=dist-mongoc /out/ /

# Prepare local Coturn sources for building.
COPY CMakeLists.txt \
     configure \
     INSTALL \
     LICENSE LICENSE.OpenSSL \
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
RUN if [ "${coturn_git_ref}" != 'HEAD' ]; then true \
 && rm -rf /app/* \
 && git init \
 && git remote add origin https://github.com/coturn/coturn \
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
COPY docker/coturn/debian/rootfs/ /out/
RUN chmod +x /out/usr/local/bin/docker-entrypoint.sh \
             /out/usr/local/bin/detect-external-ip.sh
RUN ln -s /usr/local/bin/detect-external-ip.sh \
          /out/usr/local/bin/detect-external-ip
RUN chown -R nobody:nogroup /out/var/lib/coturn/

# Re-export mongo-c-driver distribution.
COPY --from=dist-mongoc /out/ /out/




#
# Stage 'runtime' creates final Docker image to use in runtime.
#

# https://hub.docker.com/_/debian
FROM debian:${debian_ver}-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/coturn/coturn"

# Update system packages.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends --no-install-suggests \
            ca-certificates \
 && update-ca-certificates \
 # Install Coturn dependencies.
 && apt-get install -y --no-install-recommends --no-install-suggests \
            libevent-2.1-6 libevent-core-2.1-6 libevent-extra-2.1-6 \
            libevent-openssl-2.1-6 libevent-pthreads-2.1-6 \
            libssl1.1 \
            libpq5 libmariadb3 libsqlite3-0 \
            libhiredis0.14 \
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

EXPOSE 3478 3478/udp

VOLUME ["/var/lib/coturn"]

ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["--log-file=stdout", "--external-ip=$(detect-external-ip)"]
