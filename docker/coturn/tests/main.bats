#!/usr/bin/env bats


@test "Built on correct arch" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    'uname -m'
  [ "$status" -eq 0 ]
  if [ "$PLATFORM" = "linux/amd64" ]; then
    [ "$output" = "x86_64" ]
  elif [ "$PLATFORM" = "linux/arm64" ]; then
    [ "$output" = "aarch64" ]
  elif [ "$PLATFORM" = "linux/arm/v6" ]; then
    [ "$output" = "armv7l" ]
  elif [ "$PLATFORM" = "linux/arm/v7" ]; then
    [ "$output" = "armv7l" ]
  else
    [ "$output" = "$(echo $PLATFORM | cut -d '/' -f2-)" ]
  fi
}


@test "Coturn is installed" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    'which turnserver'
  [ "$status" -eq 0 ]
}

@test "Coturn runs ok" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    'turnserver -h'
  [ "$status" -eq 0 ]
}

@test "Coturn has correct version" {
  [ -z "$COTURN_VERSION" ] && skip

  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'Version Coturn' \
                                     | cut -d ' ' -f2 \
                                     | cut -d '-' -f2"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
  actual="$output"

  [ "$actual" = "$COTURN_VERSION" ]
}


@test "TLS supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'TLS supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "DTLS supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'DTLS supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "DTLS 1.2 supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'DTLS 1.2 supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "TURN/STUN ALPN supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'TURN/STUN ALPN supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "oAuth supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep '(oAuth) supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}


@test "SQLite supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'SQLite supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "Redis supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'Redis supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "PostgreSQL supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'PostgreSQL supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "MySQL supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'MySQL supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "MongoDB supported" {
  run docker run --rm --platform $PLATFORM --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'MongoDB supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}
