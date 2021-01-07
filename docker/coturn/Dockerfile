### 1. stage: create build image
FROM debian:stable AS coturn-build

ENV BUILD_PREFIX /usr/local/src

# Install build dependencies
RUN export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get install -y build-essential git debhelper dpkg-dev pkg-config libssl-dev libevent-dev sqlite3 libsqlite3-dev postgresql-client libpq-dev default-mysql-client default-libmysqlclient-dev libhiredis-dev libmongoc-dev libbson-dev libsystemd-dev

# Clone Coturn
WORKDIR ${BUILD_PREFIX}
RUN git clone https://github.com/coturn/coturn.git

# Build Coturn
WORKDIR ${BUILD_PREFIX}/coturn
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
	apt-get install -y libc6 libevent-core-2.1-6 libevent-extra-2.1-6 libevent-openssl-2.1-6 libevent-pthreads-2.1-6 libhiredis0.14 libmariadbclient-dev libpq5 libsqlite3-0 libssl1.1 libmongoc-1.0-0 libbson-1.0-0
RUN apt-get install -y default-mysql-client postgresql-client redis-tools

# Workaround for MongoDB
RUN ln -s /bin/echo /bin/systemctl

# Install MongoDB
RUN apt-get update && \
  apt-get install -y wget gnupg && \
  wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | apt-key add - && \
  echo "deb http://repo.mongodb.org/apt/debian stretch/mongodb-org/4.4 main" | tee /etc/apt/sources.list.d/mongodb-org-4.4.list && \
  echo "deb http://deb.debian.org/debian/ stretch main" | tee /etc/apt/sources.list.d/debian-stretch.list && \
  apt-get update && \
  apt-get install -y libcurl3 mongodb-org mongodb-org-server mongodb-org

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
