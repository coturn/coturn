#!/usr/bin/env bats


@test "Coturn is installed" {
  run docker run --rm --entrypoint sh $IMAGE -c 'which turnserver'
  [ "$status" -eq 0 ]
}

@test "Coturn runs ok" {
  run docker run --rm --entrypoint sh $IMAGE -c 'turnserver -h'
  [ "$status" -eq 0 ]
}

@test "Coturn has correct version" {
  run sh -c "grep 'ARG coturn_ver=' Dockerfile | cut -d '=' -f2"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
  expected="$output"

  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'Version Coturn' | cut -d ' ' -f2 \
                                           | cut -d '-' -f2"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
  actual="$output"

  [ "$actual" = "$expected" ]
}


@test "TLS supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'TLS supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "DTLS supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'DTLS supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "DTLS 1.2 supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'DTLS 1.2 supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "TURN/STUN ALPN supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'TURN/STUN ALPN supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "oAuth supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep '(oAuth) supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}


@test "SQLite supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'SQLite supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "Redis supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'Redis supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "PostgreSQL supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'PostgreSQL supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "MySQL supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'MySQL supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "MongoDB supported" {
  run docker run --rm --entrypoint sh $IMAGE -c \
    "turnserver -o | grep 'MongoDB supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}
