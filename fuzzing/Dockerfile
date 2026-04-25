FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      clang \
      cmake \
      g++ \
      libclang-rt-18-dev \
      libevent-dev \
      libhiredis-dev \
      libmariadb-dev \
      libmongoc-dev \
      libpq-dev \
      libsqlite3-dev \
      libssl-dev \
      make \
      pkg-config \
      tar \
      unzip \
 && rm -rf /var/lib/apt/lists/*

ENV CC=clang
ENV CXX=clang++

WORKDIR /src

ENTRYPOINT ["/usr/local/bin/coturn-fuzz-local"]

COPY docker-entrypoint.sh /usr/local/bin/coturn-fuzz-local
RUN chmod +x /usr/local/bin/coturn-fuzz-local
