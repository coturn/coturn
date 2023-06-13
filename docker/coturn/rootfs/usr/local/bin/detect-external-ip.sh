#!/usr/bin/env sh
# shellcheck shell=dash

#/ Use DNS to find out about the external IP of the running system.
#/
#/ This script is useful when running from a machine that sits behind a NAT.
#/ Due to how NAT works, machines behind it belong to an internal or private
#/ subnet, with a different address space than the external or public side.
#/
#/ Typically it is possible to make an HTTP request to a number of providers
#/ that offer the external IP in their response body (eg: ifconfig.me). However,
#/ why do a slow and heavy HTTP request, when DNS exists and is much faster?
#/ Well established providers such as OpenDNS or Google offer special hostnames
#/ that, when resolved, will actually return the IP address of the caller.
#/
#/ https://unix.stackexchange.com/questions/22615/how-can-i-get-my-external-ip-address-in-a-shell-script/81699#81699
#/
#/
#/ Arguments
#/ ---------
#/
#/ --ipv4
#/
#/   Find the external IPv4 address.
#/   Optional. Default: Enabled.
#/
#/ --ipv6
#/
#/   Find the external IPv6 address.
#/   Optional. Default: Disabled.



# Shell setup
# ===========

# Shell options for strict error checking.
for OPTION in errexit errtrace pipefail nounset; do
  set -o | grep -wq "$OPTION" && set -o "$OPTION"
done

# Trace all commands (to stderr).
#set -o xtrace



# Shortcut: REAL_EXTERNAL_IP
# ==========================

if [ -n "${REAL_EXTERNAL_IP:-}" ]; then
  echo "$REAL_EXTERNAL_IP"
  exit 0
fi



# Parse call arguments
# ====================

CFG_IPV4="true"

while [ $# -gt 0 ]; do
  case "${1-}" in
    --ipv4) CFG_IPV4="true" ;;
    --ipv6) CFG_IPV4="false" ;;
    *)
      echo "Invalid argument: '${1-}'" >&2
      exit 1
      ;;
  esac
  shift
done



# Discover the external IP address
# ================================

if [ "$CFG_IPV4" = "true" ]; then
  COMMANDS='dig @resolver1.opendns.com myip.opendns.com A -4 +short
            dig @ns1.google.com o-o.myaddr.l.google.com TXT -4 +short | tr -d \"
            dig @1.1.1.1 whoami.cloudflare TXT CH -4 +short | tr -d \"
            dig @ns1-1.akamaitech.net whoami.akamai.net A -4 +short'

  is_valid_ip() {
    # Check if the input looks like an IPv4 address.
    # Doesn't check if the actual values are valid; assumes they are.
    echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  }
else
  COMMANDS='dig @resolver1.opendns.com myip.opendns.com AAAA -6 +short
            dig @ns1.google.com o-o.myaddr.l.google.com TXT -6 +short | tr -d \"
            dig @2606:4700:4700::1111 whoami.cloudflare TXT CH -6 +short | tr -d \"'

  is_valid_ip() {
    # Check if the input looks like an IPv6 address.
    # It's almost impossible to check the IPv6 representation because it
    # varies wildly, so just check that there are at least 2 colons.
    [ "$(echo "$1" | awk -F':' '{print NF-1}')" -ge 2 ]
  }
fi

IFS="$(printf '\nx')" && IFS="${IFS%x}"
for COMMAND in $COMMANDS; do
  if IP="$(eval "$COMMAND 2>/dev/null")" && is_valid_ip "$IP"; then
    printf '%s' "$IP"
    exit 0
  fi
done

echo "[$0] All providers failed" >&2
exit 1
