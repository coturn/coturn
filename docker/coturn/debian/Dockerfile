#
# Dockerfile of coturn/coturn:debian Docker image.
#

ARG debian_ver=buster




#
# Stage 'dist-coturn' creates Coturn distribution.
#

# https://hub.docker.com/_/debian
FROM debian:${debian_ver}-slim AS dist-coturn

ARG coturn_git_ref=HEAD

# Install tools for building.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-install-suggests \
            autoconf coreutils g++ git libtool make pkg-config

# Install Coturn build dependencies.
RUN apt-get install -y --no-install-recommends --no-install-suggests \
            libevent-dev \
            libssl-dev \
            libpq-dev libmariadb-dev libsqlite3-dev \
            libhiredis-dev \
            libmongoc-dev

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
RUN if [ "${coturn_git_ref}" != 'HEAD' ]; then true \
 && rm -rf /app/* \
 && git init \
 && git remote add origin https://github.com/coturn/coturn \
 && git pull origin "${coturn_git_ref}" \
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
            libmongoc-1.0-0 \
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
