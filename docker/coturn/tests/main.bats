#!/usr/bin/env bats


@test "Coturn is installed" {
  run docker run --rm --entrypoint sh $IMAGE -c 'which turnserver'
  [ "$status" -eq 0 ]
}

@test "Coturn runs ok" {
  run docker run --rm --entrypoint sh $IMAGE -c 'turnserver -h'
  [ "$status" -eq 0 ]
}


@test "TLS supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'TLS supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "DTLS supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'DTLS supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "DTLS 1.2 supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'DTLS 1.2 supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "TURN/STUN ALPN supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'TURN/STUN ALPN supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "oAuth supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep '(oAuth) supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}


@test "SQLite supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'SQLite supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "Redis supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'Redis supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "PostgreSQL supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'PostgreSQL supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "MySQL supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'MySQL supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "MongoDB supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'MongoDB supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}
