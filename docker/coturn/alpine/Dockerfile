#
# Dockerfile of coturn/coturn:alpine Docker image.
#

ARG alpine_ver=3.13
ARG coturn_git_ref=-




#
# Stage 'dist-coturn' creates Coturn distribution.
#

# https://hub.docker.com/_/alpine
FROM alpine:${alpine_ver} AS dist-coturn

# Install tools for building.
RUN apk update \
 && apk add --no-cache --virtual .tool-deps \
        autoconf coreutils g++ git libtool make

# Install Coturn build dependencies.
RUN apk add --no-cache --virtual .build-deps \
        linux-headers \
        libevent-dev \
        openssl-dev \
        postgresql-dev mariadb-connector-c-dev sqlite-dev \
        hiredis-dev \
        mongo-c-driver-dev

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
RUN if [ ! "${coturn_git_ref}" = '-' ]; then true \
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
COPY docker/coturn/rootfs/ /out/
RUN chmod +x /out/usr/local/bin/docker-entrypoint.sh \
             /out/usr/local/bin/detect-external-ip.sh \
 && ln -s /usr/local/bin/detect-external-ip.sh \
          /out/usr/local/bin/detect-external-ip




#
# Stage 'runtime' creates final Docker image to use in runtime.
#

# https://hub.docker.com/_/alpine
FROM alpine:${alpine_ver} AS runtime

# Update system packages.
RUN apk update \
 && apk upgrade \
 && apk add --no-cache ca-certificates \
 && update-ca-certificates \
 # Install Coturn dependencies.
 && apk add --no-cache \
        libevent \
        libcrypto1.1 libssl1.1 \
        libpq mariadb-connector-c sqlite-libs \
        hiredis \
        mongo-c-driver \
 # Cleanup unnecessary stuff.
 && rm -rf /var/cache/apk/*

# Install Coturn distribution.
COPY --from=dist-coturn /out/ /

# Allow non-root using privileged ports.
RUN apk add --no-cache libcap \
 && setcap CAP_NET_BIND_SERVICE=+ep /usr/bin/turnserver \
 # Cleanup unnecessary stuff.
 && rm -rf /var/cache/apk/*

EXPOSE 3478 3478/udp

VOLUME ["/var/lib/coturn"]

ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["--log-file=stdout", "--external-ip=$(detect-external-ip)"]
