### 1. stage: create build image
FROM debian:stable AS coturn-build

ENV BUILD_PREFIX /usr/local/src

# Install build dependencies
RUN export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get install -y build-essential git debhelper dpkg-dev libssl-dev libevent-dev sqlite3 libsqlite3-dev postgresql-client libpq-dev default-mysql-client default-libmysqlclient-dev libhiredis-dev libmongoc-dev libbson-dev

# Clone coTURN
WORKDIR ${BUILD_PREFIX}
RUN git clone https://github.com/coturn/coturn.git

# Build coTURN
WORKDIR coturn
RUN ./configure
RUN make

### 2. stage: create production image

FROM debian:stable AS coturn

ENV INSTALL_PREFIX /usr/local
ENV BUILD_PREFIX /usr/local/src
ENV TURNSERVER_GROUP turnserver
ENV TURNSERVER_USER turnserver

COPY --from=coturn-build ${BUILD_PREFIX}/coturn/bin/ ${INSTALL_PREFIX}/bin/
COPY --from=coturn-build ${BUILD_PREFIX}/coturn/man/ ${INSTALL_PREFIX}/man/
#COPY turnserver.conf ${INSTALL_PREFIX}/etc
COPY --from=coturn-build ${BUILD_PREFIX}/coturn/sqlite/turndb ${INSTALL_PREFIX}/var/db/turndb
COPY --from=coturn-build ${BUILD_PREFIX}/coturn/turndb ${INSTALL_PREFIX}/turndb
# Install lib dependencies
RUN export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get install -y libc6>=2.15 libevent-core-2.0-5>=2.0.10-stable libevent-extra-2.0-5>=2.0.10-stable libevent-openssl-2.0-5>=2.0.10-stable libevent-pthreads-2.0-5>=2.0.10-stable libhiredis0.13>=0.13.1 libmariadbclient18>=5.5.36 libpq5>=8.4~ libsqlite3-0>=3.6.0 libssl1.1>=1.1.0 libmongoc-1.0 libbson-1.0
RUN	apt-get install -y mysql-client postgresql-client redis-tools mongodb-clients

RUN if ! getent group "$TURNSERVER_GROUP" >/dev/null; then \
        addgroup --system "$TURNSERVER_GROUP" || exit 1 ;\
    fi \
    && \
    if ! getent passwd "$TURNSERVER_USER" >/dev/null; then \
        adduser --system \
           --home / \
           --shell /bin/false \
           --no-create-home \
           --ingroup "$TURNSERVER_GROUP" \
           --disabled-password \
           --disabled-login \
           --gecos "turnserver daemon" \
               "$TURNSERVER_USER" || exit 1; \
    fi


# set startup parameters
# SUTN/TURN PORTS
EXPOSE 3478 3479 3478/udp 3479/udp 80 80/udp
EXPOSE 5349 5350 5349/udp 5350/udp 443 443/udp
# CLI
EXPOSE 5766
# Relay Ports
EXPOSE 49152-65535 49152-65535/udp

#COPY ./docker-entrypoint.sh /
#ENTRYPOINT ["/docker-entrypoint.sh"]

WORKDIR ${INSTALL_PREFIX}
CMD ${INSTALL_PREFIX}/bin/turnserver
