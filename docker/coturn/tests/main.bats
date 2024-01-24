#!/usr/bin/env bats


@test "Built on correct arch" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    'uname -m'
  [ "$status" -eq 0 ]
  if [ "$PLATFORM" = "linux/amd64" ]; then
    [ "$output" = "x86_64" ]
  elif [ "$PLATFORM" = "linux/arm/v6" ]; then
    [ "$output" = "armv7l" ]
  elif [ "$PLATFORM" = "linux/arm/v7" ]; then
    [ "$output" = "armv7l" ]
  elif [ "$PLATFORM" = "linux/arm64/v8" ]; then
    [ "$output" = "aarch64" ]
  elif [ "$PLATFORM" = "linux/386" ]; then
    [ "$output" = "x86_64" ]
  else
    [ "$output" = "$(echo $PLATFORM | cut -d '/' -f2-)" ]
  fi
}


@test "Coturn is installed" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    'which turnserver'
  [ "$status" -eq 0 ]
}

@test "Coturn runs ok" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    'turnserver -h'
  [ "$status" -eq 0 ]
}

@test "Coturn has correct version" {
  [ -z "$COTURN_VERSION" ] && skip

  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep -m 1 'Version Coturn' \
                                     | cut -d ' ' -f6 \
                                     | cut -d '-' -f2"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
  actual="$output"

  [ "$actual" = "$COTURN_VERSION" ]
}


@test "TLS 1.3 supported" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'TLS 1.3 supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "DTLS 1.2 supported" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'DTLS 1.2 supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "TURN/STUN ALPN supported" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'TURN/STUN ALPN supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "oAuth supported" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep '(oAuth) supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}


@test "SQLite supported" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'SQLite supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "Redis supported" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'Redis supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "PostgreSQL supported" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'PostgreSQL supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "MySQL supported" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'MySQL supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "MongoDB supported" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout | grep 'MongoDB supported'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}

@test "Prometheus supported" {
  # Support of Prometheus is not displayed in the output,
  # but using --prometheus flag does the job.
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    "turnserver -o --log-file=stdout --prometheus | grep 'Version Coturn'"
  [ "$status" -eq 0 ]
  [ ! "$output" = '' ]
}


@test "detect-external-ip is present" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    'which detect-external-ip'
  [ "$status" -eq 0 ]
}

@test "detect-external-ip runs ok" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    'detect-external-ip'
  [ "$status" -eq 0 ]
}

@test "detect-external-ip returns valid IPv4" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    'detect-external-ip --ipv4'
  [ "$status" -eq 0 ]

  run validate_ipv4 "$output"
  [ "$status" -eq 0 ]
}

@test "detect-external-ip returns valid IPv6" {
  [ -z "$TEST_IPV6" ] && skip

  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    'detect-external-ip --ipv6'
  [ "$status" -eq 0 ]

  run validate_ipv6 "$output"
  [ "$status" -eq 0 ]
}

@test "detect-external-ip returns IPv4 by default" {
  run docker run --rm --pull never --platform $PLATFORM \
                 --entrypoint sh $IMAGE -c \
    'detect-external-ip --ipv4'
  [ "$status" -eq 0 ]

  run validate_ipv4 "$output"
  [ "$status" -eq 0 ]
}


#
# Helpers
#

# Tests the IP address to be a valid IPv4 address.
function validate_ipv4() {
  local ip=$1
  local stat=1

  if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    OIFS=$IFS
    IFS='.'
    ip=($ip)
    IFS=$OIFS
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
    && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
  fi
  return $stat
}

# Tests the IP address to be a valid IPv6 address.
function validate_ipv6() {
  local ip=$1
  local stat=1

  if [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
    stat=0
  fi
  return $stat
}
